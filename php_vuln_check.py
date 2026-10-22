#!/usr/bin/env python3
"""php-vuln-check: find PHP installs exposed to known PHP vulnerabilities.

Starts with PHP2Shell (CVE-2026-109618 / CVE-2026-109619). Checks servers,
Docker images and CI pipelines without sending exploit traffic: it reads
versions, vendor changelogs and config, never probes a target into failing.

Single file, standard library only, Python 3.6+.
https://github.com/jake-bowser/php-vuln-check  (MIT License)
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
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

__version__ = "0.1.0"
REPO_URL = "https://github.com/jake-bowser/php-vuln-check"

VULNERABLE, REVIEW, PATCHED, ERROR = "VULNERABLE", "REVIEW", "PATCHED", "ERROR"
STATUS_ORDER = {VULNERABLE: 0, ERROR: 1, REVIEW: 2, PATCHED: 3}

# One entry per advisory. Adding the next PHP CVE means adding one dict here.
ADVISORIES = [
    {
        "id": "PHP2SHELL",
        "name": "PHP2Shell",
        "cves": ["CVE-2026-109618", "CVE-2026-109619"],
        "severity": "critical",
        "cvss": "9.2 (CVSS v4.0)",
        "published": "2026-10-21",
        "min_affected": "5.4.0",
        "fixed": {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"},
        "summary": (
            "Unauthenticated remote code execution in the PHP engine (Apache mod_php "
            "and PHP-FPM), triggered by a fatal error such as running out of memory "
            "during a multipart/form-data request."
        ),
        "mitigations": [
            "Update PHP to a fixed release, or to a vendor build whose changelog lists both CVEs, then restart PHP-FPM / Apache.",
            "Temporary and partial: block multipart/form-data requests at the web server (this breaks file uploads).",
            "Temporary and partial: set session.upload_progress.enabled=0 and memory_limit=-1 (watch memory use).",
        ],
        "references": [
            {"title": "Sansec research", "url": "https://sansec.io/research/php2shell"},
            {"title": "Help Net Security", "url": "https://www.helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619/"},
            {"title": "watchTowr FAQ", "url": "https://watchtowr.com/intelligence/php-cve-2026-109618-faq/"},
        ],
    }
]

ADVISORIES_BY_ID = {a["id"]: a for a in ADVISORIES}

CONFIG_KEYS = ("session.upload_progress.enabled", "memory_limit")

VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(.*)$")
PRERELEASE_RE = re.compile(r"(?<![A-Za-z])(alpha|beta|rc|dev)(?![A-Za-z])", re.I)
DASH_V_RE = re.compile(r"^PHP (\d+\.\d+\.\d+)(\S*)\s+\(([^)]+)\)")
STATIC_RE = re.compile(rb"X-Powered-By: PHP/(\d+\.\d+\.\d+[0-9A-Za-z.+~_-]*)")
HEADER_RE = re.compile(r"PHP/(\d+\.\d+\.\d+\S*)")


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


def evaluate(adv, version, backports=None):
    """Judge one PHP version against one advisory.

    backports: set of the advisory's CVE ids found in the vendor changelog, an
    empty set when a changelog was read and held none, or None when there was
    no changelog to read.
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
        why = "branch %s is end-of-life and has no upstream fix" % branch

    if len(found) == len(cves):
        return PATCHED, "%s, but the vendor changelog lists fixes for %s" % (why, " and ".join(cves))
    if found:
        return VULNERABLE, "%s; the vendor changelog only mentions %s" % (why, ", ".join(found))
    if backports is None:
        return VULNERABLE, "%s; no vendor changelog was available to confirm a backport" % why
    return VULNERABLE, "%s; no vendor backport found in the changelog" % why


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
    return VULNERABLE, "branch %s is end-of-life with no upstream fix; pulling a newer image on this branch cannot fix it" % branch


def package_upstream_version(pkg_version):
    """'1:8.2.30+dfsg-1~deb12u1' -> '8.2.30+dfsg-1~deb12u1' (epoch dropped)."""
    return re.sub(r"^\d+:", "", pkg_version or "")


# --------------------------------------------------------------------------
# Running commands and reading the host
# --------------------------------------------------------------------------

def run(cmd, timeout=20, stdin=None):
    try:
        p = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=stdin,
            universal_newlines=True, errors="replace", timeout=timeout,
        )
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, "", str(exc)


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
                m = STATIC_RE.search(tail + chunk)
                if m:
                    return m.group(1).decode("ascii", "replace")
                tail = chunk[-256:]
    except OSError:
        return None
    return None


def php_dash_v(path):
    """Run `php -n -v`; return (version_text, sapi) or (None, None)."""
    code, out, _ = run([path, "-n", "-v"], timeout=15)
    if code != 0 or not out:
        return None, None
    m = DASH_V_RE.match(out.splitlines()[0])
    if not m:
        return None, None
    return m.group(1) + m.group(2), m.group(3)


def parse_ini_dump(text):
    values = {}
    for key in CONFIG_KEYS:
        m = re.search(r"^%s\s*=>\s*(\S+)" % re.escape(key), text, re.M)
        if m:
            values[key] = m.group(1)
    return values


def php_config(path):
    code, out, _ = run([path, "-i"], timeout=30)
    return parse_ini_dump(out) if code == 0 else {}


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
    code, out, _ = run(["dpkg", "-S", path])
    if code != 0 or not out.strip():
        return None
    names = out.splitlines()[0].rsplit(": ", 1)[0]
    pkg = names.split(",")[0].strip().split(":")[0]
    code, info, _ = run(["dpkg-query", "-W", "-f", "${Version}\n${source:Package}\n", pkg])
    lines = info.splitlines() if code == 0 else []
    return {
        "manager": "dpkg", "name": pkg,
        "version": lines[0] if lines else "",
        "source": lines[1] if len(lines) > 1 else "",
    }


def _rpm_owner(path):
    code, out, _ = run(["rpm", "-qf", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n", path])
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


def _read_text(path):
    try:
        if path.endswith(".gz"):
            with gzip.open(path, "rt", errors="replace") as fh:
                return fh.read()
        with io.open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def dpkg_changelog(owner, doc_root="/usr/share/doc"):
    names = [owner["name"], owner.get("source") or "",
             re.sub(r"-[a-z0-9]+$", "-common", owner["name"])]
    for name in dict.fromkeys(n for n in names if n):
        for fname in ("changelog.Debian.gz", "changelog.gz", "changelog"):
            text = _read_text(os.path.join(doc_root, name, fname))
            if text:
                return text
    return None


def vendor_changelog(owner, path, cves):
    """Return the set of `cves` named in the owning package's changelog, or None."""
    if owner["manager"] == "dpkg":
        text = dpkg_changelog(owner)
    else:
        code, out, _ = run(["rpm", "-qf", path, "--changelog"], timeout=90)
        text = out if code == 0 else None
    if not text:
        return None
    return set(c for c in cves if c in text)


# --------------------------------------------------------------------------
# Finding model
# --------------------------------------------------------------------------

def fixed_in(adv, version):
    """The release that fixes this branch, or the list of fixed releases when it is unknown."""
    fixed = adv["fixed"]
    parts = (version or "").split(".")
    if len(parts) >= 2:
        branch = ".".join(parts[:2])
        if branch in fixed:
            return fixed[branch]
        oldest = min(fixed, key=_tuple)
        if (int(parts[0]), int(parts[1])) < _tuple(oldest)[:2]:
            return "no upstream fix; move to %s or later, or use a vendor backport" % fixed[oldest]
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
        dirs.extend(p for p in os.environ.get("PATH", "").split(os.pathsep) if p)
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


def inspect_target(path, kind, no_exec, advisories):
    owner = package_owner(path)
    sapi = "apache2handler" if kind == "mod_php" else None
    version_text, method, config = None, None, {}

    if kind == "binary" and not no_exec:
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

    version = parse_version(version_text) if version_text else None
    package = "%s %s" % (owner["name"], owner["version"]) if owner else None
    confidence = {"exec": "high", "static": "high", "package": "medium"}.get(method)

    findings = []
    for adv in advisories:
        if version is None:
            status = REVIEW
            reason = "could not determine the PHP version" + (" (try again without --no-exec)" if no_exec else "")
        else:
            status, reason = evaluate(adv, version, None)
            if status == VULNERABLE and owner:
                status, reason = evaluate(adv, version, vendor_changelog(owner, path, adv["cves"]))
        findings.append(make_finding(
            adv, kind, path, status, reason, sapi=sapi, package=package, config=config,
            version="%d.%d.%d" % version[:3] if version else None, confidence=confidence,
            host=socket.gethostname(),
        ))
    return findings


def cmd_scan(args, advisories):
    targets = discover(args.path or [], defaults=not args.no_defaults)
    findings = []
    for path, kind in targets:
        findings.extend(inspect_target(path, kind, args.no_exec, advisories))
    notes = []
    if not targets:
        notes.append("No PHP binaries or Apache mod_php modules were found in the searched locations. "
                     "Use --path DIR to point at a custom install.")
    return findings, notes


# --------------------------------------------------------------------------
# images: Dockerfiles, compose files, Kubernetes manifests, running containers
# --------------------------------------------------------------------------

FROM_RE = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", re.I)
ARG_RE = re.compile(r"^\s*ARG\s+([A-Za-z_]\w*)(?:=(.*))?\s*$")
YAML_IMAGE_RE = re.compile(r"^\s*-?\s*image:\s*['\"]?([^\s'\"#]+)")
VAR_RE = re.compile(r"\$\{(\w+)(?::?-([^}]*))?\}|\$(\w+)")
TAG_VERSION_RE = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(.*)$")
BUNDLED_RE = re.compile(r"php(\d+)\.(\d+)(?:\.(\d+))?")
OFFICIAL_PHP = {"php", "library/php", "docker.io/library/php", "index.docker.io/library/php",
                "registry.hub.docker.com/library/php"}
PHP_IMAGE_NAMES = {"php", "php-fpm", "php-cli", "php-apache", "php-nginx", "php-fpm-nginx"}
IMAGE_SKIP_DIRS = {".git", "node_modules", ".venv", "vendor", "__pycache__"}


def substitute(text, variables):
    def repl(m):
        name = m.group(1) or m.group(3)
        if name in variables:
            return variables[name]
        if m.group(2) is not None:
            return m.group(2)
        return m.group(0)
    return VAR_RE.sub(repl, text)


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
    return (low in ("dockerfile", "containerfile") or low.startswith(("dockerfile.", "containerfile."))
            or low.endswith((".dockerfile", ".containerfile")))


def _file_image_refs(path):
    """Yield (line_number, ref) for each image reference in one file."""
    text = _read_text(path)
    if text is None or len(text) > 2 * 1024 * 1024:
        return
    lines = text.splitlines()
    if _is_dockerfile(os.path.basename(path)):
        variables, stages = {}, set()
        for number, line in enumerate(lines, 1):
            arg = ARG_RE.match(line)
            if arg and arg.group(2) is not None:
                variables[arg.group(1)] = arg.group(2).strip().strip("'\"")
                continue
            m = FROM_RE.match(line)
            if not m:
                continue
            ref = substitute(m.group(1), variables)
            if m.group(2):
                stages.add(m.group(2).lower())
            if ref.lower() == "scratch" or ref.lower() in stages:
                continue
            yield number, ref
    elif path.lower().endswith((".yml", ".yaml")):
        for number, line in enumerate(lines, 1):
            m = YAML_IMAGE_RE.match(line)
            if m:
                yield number, substitute(m.group(1), {})


def collect_image_refs(roots):
    for root in roots:
        if os.path.isfile(root):
            for number, ref in _file_image_refs(root):
                yield root, number, ref
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in IMAGE_SKIP_DIRS)
            for fname in sorted(filenames):
                path = os.path.join(dirpath, fname)
                if _is_dockerfile(fname) or fname.lower().endswith((".yml", ".yaml")):
                    for number, ref in _file_image_refs(path):
                        yield path, number, ref


def _opt_int(text):
    return int(text) if text else None


def evaluate_image(adv, ref):
    """Return (status, reason, version) for an image reference, or None if it is not PHP."""
    if "$" in ref:
        if "php" not in ref.lower():
            return None
        return REVIEW, "the image reference uses a build variable this tool cannot resolve", None
    name, tag, digest = parse_image(ref)
    last = name.rsplit("/", 1)[-1].lower()
    php_image = name.lower() in OFFICIAL_PHP or last in PHP_IMAGE_NAMES
    match = None
    if php_image:
        m = TAG_VERSION_RE.match(tag or "")
        if m:
            match = (int(m.group(1)), _opt_int(m.group(2)), _opt_int(m.group(3)), m.group(4))
    else:
        # Images that bundle PHP and say so in the tag, e.g. wordpress:6.8-php8.3-apache.
        m = BUNDLED_RE.search(tag or "")
        if not m:
            return None
        php_image = True
        match = (int(m.group(1)), int(m.group(2)), _opt_int(m.group(3)), "")
    if match is None:
        what = "pinned only by digest" if digest and not tag else "using an unpinned tag"
        return REVIEW, "PHP image %s; the PHP version cannot be read from the reference" % what, None
    major, minor, patch, rest = match
    if PRERELEASE_RE.search(rest):
        return REVIEW, "pre-release PHP image tag; compare it with the release notes", None
    if minor is not None and patch is not None:
        status, reason = evaluate(adv, (major, minor, patch, ""), None)
        if status == VULNERABLE:
            reason = reason.replace("; no vendor changelog was available to confirm a backport", "")
        return status, reason, "%d.%d.%d" % (major, minor, patch)
    if minor is not None:
        status, reason = evaluate_branch_only(adv, major, minor)
        return status, reason, "%d.%d" % (major, minor)
    return REVIEW, "tag pins only the major version (PHP %d); pin a full version such as 8.3.36 or later" % major, str(major)


def image_findings(advisories, refs):
    findings = []
    cwd = os.getcwd()
    for path, number, ref in refs:
        for adv in advisories:
            verdict = evaluate_image(adv, ref)
            if verdict is None:
                continue
            status, reason, version = verdict
            shown = os.path.relpath(path, cwd) if path and not os.path.relpath(path, cwd).startswith("..") else path
            findings.append(make_finding(
                adv, "image", ref, status, reason, version=version,
                confidence="high" if version and version.count(".") == 2 else "medium",
                location={"file": shown, "line": number} if shown else None,
            ))
    return findings


def cmd_images(args, advisories):
    paths = args.paths or ([] if args.image or args.docker else ["."])
    refs = list(collect_image_refs(paths))
    notes = []
    if args.image:
        refs.extend((None, 0, ref) for ref in args.image)
    if args.docker:
        code, out, err = run(["docker", "ps", "--format", "{{.Image}}"], timeout=30)
        if code != 0:
            notes.append("Could not list running containers (%s)." % (err.strip() or "docker not available"))
        else:
            refs.extend((None, 0, ref.strip()) for ref in sorted(set(out.splitlines())) if ref.strip())
    findings = image_findings(advisories, refs)
    if not findings:
        notes.append("No PHP image references found.")
    return findings, notes


# --------------------------------------------------------------------------
# url: one ordinary GET, read the advertised version
# --------------------------------------------------------------------------

def check_url(url, advisories, timeout):
    headers = {"User-Agent": "php-vuln-check/%s (+%s)" % (__version__, REPO_URL)}
    header = None
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout) as resp:
            header = resp.headers.get("X-Powered-By", "")
    except urllib.error.HTTPError as exc:
        header = exc.headers.get("X-Powered-By", "") if exc.headers else ""
    except Exception as exc:  # DNS, TLS, timeout, refused
        return [error_finding(adv, "url", url, "request failed: %s" % exc) for adv in advisories]

    m = HEADER_RE.search(header or "")
    findings = []
    for adv in advisories:
        if not m:
            findings.append(make_finding(
                adv, "url", url, REVIEW,
                "no PHP version is advertised (expose_php is off, or a proxy strips X-Powered-By); "
                "run `php-vuln-check scan` on the server", confidence="low"))
            continue
        version = parse_version(m.group(1))
        status, reason = evaluate(adv, version, None) if version else (REVIEW, "could not parse the advertised version")
        if status == VULNERABLE:
            status = REVIEW
            reason = (reason.replace("; no vendor changelog was available to confirm a backport", "") +
                      "; distro backports are invisible from outside, so confirm on the host with `php-vuln-check scan`")
        findings.append(make_finding(
            adv, "url", url, status, "the server advertises PHP/%s: %s" % (m.group(1), reason),
            version="%d.%d.%d" % version[:3] if version else None, confidence="low"))
    return findings


def cmd_url(args, advisories):
    findings = []
    for url in args.urls:
        if not re.match(r"^https?://", url):
            raise SystemExit("php-vuln-check: URLs must start with http:// or https:// (got %r)" % url)
        findings.extend(check_url(url, advisories, args.timeout))
    return findings, []


# --------------------------------------------------------------------------
# fleet: run `scan` on many hosts over SSH, nothing installed remotely
# --------------------------------------------------------------------------

def read_hosts(path):
    hosts = []
    with io.open(path, "r") as fh:
        for line in fh:
            host = line.split("#", 1)[0].strip()
            if not host:
                continue
            if host.startswith("-") or any(c.isspace() for c in host):
                raise SystemExit("php-vuln-check: refusing suspicious host entry %r in %s" % (host, path))
            hosts.append(host)
    return hosts


def fleet_one(host, script, args, advisory_ids):
    remote = ["python3", "-", "scan", "--format", "json", "--quiet"]
    if args.no_exec:
        remote.append("--no-exec")
    for adv_id in advisory_ids:
        remote.extend(["--advisory", adv_id])
    cmd = (["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=%d" % args.connect_timeout]
           + shlex.split(args.ssh_opts or "") + ["--", host, " ".join(shlex.quote(p) for p in remote)])
    code, out, err = run(cmd, timeout=args.timeout, stdin=script)
    start = out.find("{")
    try:
        report = json.loads(out[start:]) if start >= 0 else None
    except ValueError:
        report = None
    if report is None:
        first = (err.strip().splitlines() or ["no output"])[0]
        return [error_finding(ADVISORIES_BY_ID[advisory_ids[0]], "host", host,
                              "ssh or scan failed: %s" % first, host=host)]
    findings = report.get("findings", [])
    for finding in findings:
        finding["host"] = host
    if not findings:
        # Exit 0 with nothing found: say so instead of silently dropping the host.
        note = (report.get("notes") or ["no PHP found"])[0]
        return [make_finding(ADVISORIES_BY_ID[advisory_ids[0]], "host", host, PATCHED,
                             "no PHP install found (%s)" % note.rstrip("."), host=host)]
    return findings


def cmd_fleet(args, advisories):
    hosts = read_hosts(args.hosts_file)
    if not hosts:
        raise SystemExit("php-vuln-check: no hosts found in %s" % args.hosts_file)
    with io.open(os.path.abspath(__file__), "r", encoding="utf-8") as fh:
        script = fh.read()
    ids = [a["id"] for a in advisories]
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        results = list(pool.map(lambda h: fleet_one(h, script, args, ids), hosts))
    findings = [f for batch in results for f in batch]
    notes = ["Checked %d host(s) over SSH." % len(hosts)]
    return findings, notes


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def summarize(findings):
    counts = {VULNERABLE: 0, ERROR: 0, REVIEW: 0, PATCHED: 0}
    for f in findings:
        counts[f["status"]] = counts.get(f["status"], 0) + 1
    return counts


def build_report(findings, notes, mode):
    counts = summarize(findings)
    return {
        "tool": "php-vuln-check", "version": __version__, "mode": mode,
        "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {k.lower(): v for k, v in counts.items()},
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


COLORS = {VULNERABLE: "1;31", ERROR: "1;35", REVIEW: "1;33", PATCHED: "1;32"}


def render_text(report, advisories, color, quiet):
    def paint(status, text):
        return "\033[%sm%s\033[0m" % (COLORS[status], text) if color else text

    out = []
    if not quiet:
        names = "; ".join("%s (%s)" % (a["name"], ", ".join(a["cves"])) for a in advisories)
        out.append("php-vuln-check %s  ·  checking %s" % (__version__, names))
        out.append("")
    multi_host = len(set(f.get("host") for f in report["findings"] if f.get("host"))) > 1
    for f in report["findings"]:
        head = f["target"]
        if f.get("host") and (multi_host or report["mode"] == "fleet"):
            head = "%s  %s" % (f["host"], head)
        out.append("%s  %s" % (paint(f["status"], "%-10s" % f["status"]), head))
        detail = [d for d in (
            ("PHP %s" % f["version"]) if f.get("version") else None,
            f.get("sapi"), f.get("package")) if d]
        if detail:
            out.append("            " + " · ".join(detail))
        out.append("            " + f["reason"])
        if f.get("location"):
            out.append("            at %s:%s" % (f["location"]["file"], f["location"]["line"]))
        cfg = f.get("config") or {}
        if cfg:
            out.append("            config: " + " ".join("%s=%s" % kv for kv in sorted(cfg.items())))
        out.append("")
    for note in report["notes"]:
        out.append(note)
    s = report["summary"]
    out.append("Summary: %d vulnerable · %d need review · %d patched%s" % (
        s["vulnerable"], s["review"], s["patched"], (" · %d error" % s["error"]) if s["error"] else ""))
    if not quiet and (s["vulnerable"] or s["review"]):
        out.append("")
        out.append("What to do:")
        for adv in advisories:
            for step in adv["mitigations"]:
                out.append("  - " + step)
            out.append("  - Details: " + adv["references"][0]["url"])
        out.append("  - REVIEW means the tool could not prove either way; it is not a clean bill of health.")
    return "\n".join(out) + "\n"


def render_csv(report):
    buf = io.StringIO()
    cols = ["host", "advisory", "status", "kind", "target", "sapi", "version", "package",
            "fixed_in", "confidence", "reason", "file", "line"]
    writer = csv.writer(buf)
    writer.writerow(cols)
    for f in report["findings"]:
        loc = f.get("location") or {}
        row = [f.get(c) for c in cols[:-2]] + [loc.get("file"), loc.get("line")]
        writer.writerow(["" if v is None else v for v in row])
    return buf.getvalue()


def render_sarif(report, advisories):
    rules = [{
        "id": a["id"], "name": a["name"],
        "shortDescription": {"text": "%s (%s)" % (a["name"], ", ".join(a["cves"]))},
        "fullDescription": {"text": a["summary"]},
        "helpUri": a["references"][0]["url"],
        "properties": {"tags": ["security"] + a["cves"], "security-severity": "9.0"},
    } for a in advisories]
    levels = {VULNERABLE: "error", ERROR: "warning", REVIEW: "warning"}
    results = []
    for f in report["findings"]:
        if f["status"] not in levels:
            continue
        loc = f.get("location") or {}
        results.append({
            "ruleId": f["advisory"], "level": levels[f["status"]],
            "message": {"text": "%s: %s" % (f["target"], f["reason"])},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": loc.get("file") or f["target"]},
                "region": {"startLine": int(loc.get("line") or 1)},
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
    else:
        sys.stdout.write(text)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

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


def build_parser():
    common = common_options()
    parser = argparse.ArgumentParser(
        prog="php-vuln-check",
        description="Find PHP installs exposed to PHP2Shell (CVE-2026-109618 / CVE-2026-109619) and "
                    "other tracked PHP vulnerabilities. Reads versions, vendor changelogs and config; "
                    "never sends exploit traffic.",
        epilog="Exit codes: 0 clean, 1 vulnerable, 2 needs review, 3 error.  Docs: " + REPO_URL)
    parser.add_argument("--version", action="version", version="php-vuln-check " + __version__)
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser("scan", parents=[common], help="audit PHP installs on this machine (default)")
    p.add_argument("--path", action="append", metavar="DIR", help="also search DIR (or check this file); repeatable")
    p.add_argument("--no-defaults", action="store_true", help="skip the standard install locations")
    p.add_argument("--no-exec", action="store_true",
                   help="never run PHP binaries; read versions from the files and the package manager instead")

    p = sub.add_parser("images", parents=[common], help="check Dockerfiles, compose files, k8s manifests, images")
    p.add_argument("paths", nargs="*", metavar="PATH", help="files or folders to scan (default: .)")
    p.add_argument("--image", action="append", metavar="REF", help="check one image reference such as php:8.3-fpm")
    p.add_argument("--docker", action="store_true", help="also check images of running containers")

    p = sub.add_parser("url", parents=[common], help="read the PHP version a website advertises (one GET each)")
    p.add_argument("urls", nargs="+", metavar="URL")
    p.add_argument("--timeout", type=int, default=15)

    p = sub.add_parser("fleet", parents=[common], help="run `scan` on many hosts over SSH")
    p.add_argument("hosts_file", metavar="HOSTS_FILE", help="one [user@]host per line; # starts a comment")
    p.add_argument("--jobs", type=int, default=8, help="hosts to check in parallel (default: 8)")
    p.add_argument("--ssh-opts", default="", help='extra ssh options, e.g. "-i ~/.ssh/key -p 2222"')
    p.add_argument("--connect-timeout", type=int, default=10)
    p.add_argument("--timeout", type=int, default=300, help="seconds to wait for each host")
    p.add_argument("--no-exec", action="store_true", help="never run PHP binaries on the hosts")

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
    parser = build_parser()
    args = parser.parse_args(argv)
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


if __name__ == "__main__":
    sys.exit(main())
