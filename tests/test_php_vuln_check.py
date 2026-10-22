import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import php_vuln_check as pvc  # noqa: E402

ADV = pvc.ADVISORIES_BY_ID["PHP2SHELL"]
CVES = set(ADV["cves"])

FAKE_PHP = """#!/bin/sh
case "$*" in
  *-i*) echo "session.upload_progress.enabled => On => On"; echo "memory_limit => 128M => 128M";;
  *-v*) echo "PHP {version} ({sapi}) (built: Jul  1 2026 00:00:00) (NTS)"; echo "Copyright (c) The PHP Group";;
esac
"""


def write_exec(path, body):
    with open(path, "w") as fh:
        fh.write(body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)


def fake_php(path, version, sapi="cli"):
    write_exec(path, FAKE_PHP.format(version=version, sapi=sapi))


def ev(version, backports=None):
    return pvc.evaluate(ADV, pvc.parse_version(version), backports)


def cli(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = pvc.main(list(argv))
    return code, out.getvalue()


class VersionLogic(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(pvc.parse_version("8.2.30"), (8, 2, 30, ""))
        self.assertEqual(pvc.parse_version("8.1.2-1ubuntu2.14"), (8, 1, 2, "-1ubuntu2.14"))
        self.assertIsNone(pvc.parse_version("garbage"))

    def test_supported_branches_at_and_below_fix(self):
        for fixed in ("8.2.35", "8.3.36", "8.4.27", "8.5.12", "8.5.13"):
            self.assertEqual(ev(fixed)[0], pvc.PATCHED, fixed)
        for old in ("8.2.34", "8.3.35", "8.4.26", "8.5.11"):
            self.assertEqual(ev(old)[0], pvc.VULNERABLE, old)

    def test_end_of_life_branches_have_no_upstream_fix(self):
        for eol in ("8.1.99", "8.0.30", "7.4.33", "5.6.40", "5.4.0"):
            status, reason = ev(eol)
            self.assertEqual(status, pvc.VULNERABLE, eol)
            self.assertIn("end-of-life", reason)

    def test_older_than_documented_range_needs_review(self):
        self.assertEqual(ev("5.3.29")[0], pvc.REVIEW)

    def test_unknown_future_branch_needs_review(self):
        self.assertEqual(ev("9.0.1")[0], pvc.REVIEW)

    def test_prerelease_needs_review(self):
        self.assertEqual(ev("8.5.0RC1")[0], pvc.REVIEW)
        self.assertEqual(ev("8.4.0-dev")[0], pvc.REVIEW)

    def test_distro_suffix_is_not_a_prerelease(self):
        self.assertEqual(ev("8.1.2-1ubuntu2.14")[0], pvc.VULNERABLE)

    def test_full_backport_makes_old_version_patched(self):
        status, reason = ev("8.1.2", CVES)
        self.assertEqual(status, pvc.PATCHED)
        self.assertIn("vendor changelog", reason)
        self.assertEqual(ev("8.2.30", CVES)[0], pvc.PATCHED)

    def test_partial_backport_stays_vulnerable(self):
        status, reason = ev("8.1.2", {"CVE-2026-109618"})
        self.assertEqual(status, pvc.VULNERABLE)
        self.assertIn("only mentions CVE-2026-109618", reason)

    def test_no_changelog_vs_empty_changelog_reasons_differ(self):
        self.assertIn("no vendor changelog", ev("8.2.30", None)[1])
        self.assertIn("no vendor backport found", ev("8.2.30", set())[1])

    def test_fixed_in_hint(self):
        self.assertEqual(pvc.fixed_in(ADV, "8.3.30"), "8.3.36")
        self.assertIn("no upstream fix", pvc.fixed_in(ADV, "7.4.33"))
        self.assertIn("8.2.35", pvc.fixed_in(ADV, None))

    def test_package_version_epoch_stripped(self):
        self.assertEqual(pvc.package_upstream_version("1:8.2.30+dfsg-1"), "8.2.30+dfsg-1")


class Parsers(unittest.TestCase):
    def test_dash_v_formats(self):
        samples = {
            "PHP 8.3.14 (cli) (built: Nov 21 2024 17:23:55) (NTS)": ("8.3.14", "cli"),
            "PHP 8.1.2-1ubuntu2.14 (cli) (built: Jun  3 2024) (NTS)": ("8.1.2-1ubuntu2.14", "cli"),
            "PHP 8.2.30 (fpm-fcgi) (built: Jul  1 2026) (NTS)": ("8.2.30", "fpm-fcgi"),
        }
        for line, expected in samples.items():
            m = pvc.DASH_V_RE.match(line)
            self.assertEqual((m.group(1) + m.group(2), m.group(3)), expected)

    def test_ini_dump(self):
        text = "session.upload_progress.enabled => On => On\nmemory_limit => -1 => -1\nother => x => y\n"
        self.assertEqual(pvc.parse_ini_dump(text),
                         {"session.upload_progress.enabled": "On", "memory_limit": "-1"})

    def test_binary_names(self):
        for good in ("php", "php8.2", "php5-fpm", "php-fpm", "php-fpm8.2", "php-cgi", "lsphp83"):
            self.assertTrue(pvc.BIN_NAME_RE.match(good), good)
        for bad in ("php-config", "phpize", "php.ini", "phpdbg", "php8.2.bak"):
            self.assertFalse(pvc.BIN_NAME_RE.match(bad), bad)

    def test_changelog_evidence(self):
        text = "php8.2 (8.2.30-1~deb12u2) bookworm-security; urgency=high\n  * Fix CVE-2026-109618 and CVE-2026-109619\n"
        owner = {"manager": "dpkg", "name": "php8.2-cli", "version": "8.2.30-1~deb12u2", "source": "php8.2"}
        with tempfile.TemporaryDirectory() as doc:
            os.makedirs(os.path.join(doc, "php8.2-common"))
            with open(os.path.join(doc, "php8.2-common", "changelog.Debian"), "w") as fh:
                fh.write("x")
            import gzip
            with gzip.open(os.path.join(doc, "php8.2-common", "changelog.Debian.gz"), "wt") as fh:
                fh.write(text)
            got = pvc.dpkg_changelog(owner, doc_root=doc)
        self.assertEqual(set(c for c in ADV["cves"] if c in got), CVES)


class ImageLogic(unittest.TestCase):
    def verdict(self, ref):
        return pvc.evaluate_image(ADV, ref)

    def test_pinned_official_images(self):
        self.assertEqual(self.verdict("php:8.3.36-apache")[0], pvc.PATCHED)
        status, reason, version = self.verdict("php:8.3.35-fpm-alpine")
        self.assertEqual((status, version), (pvc.VULNERABLE, "8.3.35"))
        self.assertNotIn("changelog", reason)

    def test_floating_tags_need_review_unless_eol(self):
        self.assertEqual(self.verdict("php:8.3-apache")[0], pvc.REVIEW)
        self.assertEqual(self.verdict("php:8-cli")[0], pvc.REVIEW)
        self.assertEqual(self.verdict("php:latest")[0], pvc.REVIEW)
        self.assertEqual(self.verdict("php:cli")[0], pvc.REVIEW)
        self.assertEqual(self.verdict("php")[0], pvc.REVIEW)
        self.assertEqual(self.verdict("php:7.4-apache")[0], pvc.VULNERABLE)
        self.assertEqual(self.verdict("php:8.1-fpm")[0], pvc.VULNERABLE)

    def test_registry_prefixes_and_digests(self):
        self.assertEqual(self.verdict("docker.io/library/php:8.2.35")[0], pvc.PATCHED)
        self.assertEqual(self.verdict("php@sha256:abcd")[0], pvc.REVIEW)
        self.assertEqual(self.verdict("registry.local:5000/team/php-fpm:8.4.26")[0], pvc.VULNERABLE)

    def test_bundled_php_images(self):
        status, _, version = self.verdict("wordpress:6.8-php8.3-apache")
        self.assertEqual((status, version), (pvc.REVIEW, "8.3"))
        self.assertEqual(self.verdict("drupal:10-php7.4-apache")[0], pvc.VULNERABLE)

    def test_non_php_images_are_ignored(self):
        for ref in ("nginx:1.25", "phpmyadmin:5.2", "redis", "postgres:16", "node:20-alpine"):
            self.assertIsNone(self.verdict(ref), ref)

    def test_unresolved_variable(self):
        self.assertEqual(self.verdict("php:${TAG}")[0], pvc.REVIEW)
        self.assertIsNone(self.verdict("${BASE}"))

    def test_dockerfile_arg_substitution_and_stages(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "Dockerfile")
            with open(path, "w") as fh:
                fh.write("ARG PHP_VERSION=8.2.30\nFROM composer:2 AS vendor\n"
                         "FROM php:${PHP_VERSION}-fpm AS app\nFROM app AS test\nFROM scratch\n")
            refs = list(pvc.collect_image_refs([tmp]))
        self.assertEqual([(r[1], r[2]) for r in refs],
                         [(2, "composer:2"), (3, "php:8.2.30-fpm")])

    def test_compose_and_k8s_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "docker-compose.yml"), "w") as fh:
                fh.write("services:\n  web:\n    image: ${PHP_IMAGE:-php:8.3.35-apache}\n"
                         "  db:\n    image: \"postgres:16\"\n")
            with open(os.path.join(tmp, "pod.yaml"), "w") as fh:
                fh.write("spec:\n  containers:\n    - image: php:7.4-fpm\n")
            refs = sorted(r[2] for r in pvc.collect_image_refs([tmp]))
        self.assertEqual(refs, ["php:7.4-fpm", "php:8.3.35-apache", "postgres:16"])


class ScanWithFakeBinaries(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

    def scan(self, *extra):
        code, out = cli("scan", "--no-defaults", "--path", self.dir, "--format", "json", *extra)
        return code, json.loads(out)

    def test_vulnerable_binary_reports_config_and_exit_1(self):
        fake_php(os.path.join(self.dir, "php-fpm8.2"), "8.2.30", "fpm-fcgi")
        code, report = self.scan()
        self.assertEqual(code, 1)
        (finding,) = report["findings"]
        self.assertEqual(finding["status"], pvc.VULNERABLE)
        self.assertEqual(finding["version"], "8.2.30")
        self.assertEqual(finding["sapi"], "fpm-fcgi")
        self.assertEqual(finding["fixed_in"], "8.2.35")
        self.assertEqual(finding["config"]["session.upload_progress.enabled"], "On")
        self.assertEqual(finding["confidence"], "high")

    def test_patched_binary_exits_0(self):
        fake_php(os.path.join(self.dir, "php"), "8.4.27")
        code, report = self.scan()
        self.assertEqual(code, 0)
        self.assertEqual(report["summary"]["patched"], 1)

    def test_static_version_when_not_executing(self):
        with open(os.path.join(self.dir, "libphp.so"), "wb") as fh:
            fh.write(b"\x7fELF" + b"\0" * 5000 + b"X-Powered-By: PHP/8.3.20\0" + b"\0" * 100)
        code, report = self.scan()
        (finding,) = report["findings"]
        self.assertEqual((finding["kind"], finding["version"], finding["status"]),
                         ("mod_php", "8.3.20", pvc.VULNERABLE))
        self.assertEqual(finding["sapi"], "apache2handler")

    def test_no_exec_never_runs_the_binary(self):
        marker = os.path.join(self.dir, "ran")
        write_exec(os.path.join(self.dir, "php"), "#!/bin/sh\ntouch '%s'\n" % marker)
        code, report = self.scan("--no-exec")
        self.assertFalse(os.path.exists(marker))
        self.assertEqual(report["findings"][0]["status"], pvc.REVIEW)
        self.assertEqual(code, 2)

    def test_fail_on_controls_exit_code(self):
        write_exec(os.path.join(self.dir, "php"), "#!/bin/sh\nexit 1\n")
        self.assertEqual(self.scan()[0], 2)
        self.assertEqual(self.scan("--fail-on", "vulnerable")[0], 0)
        self.assertEqual(self.scan("--fail-on", "never")[0], 0)

    def test_nothing_found(self):
        code, report = self.scan()
        self.assertEqual(code, 0)
        self.assertEqual(report["findings"], [])
        self.assertTrue(report["notes"])

    def test_duplicate_symlinks_reported_once(self):
        fake_php(os.path.join(self.dir, "php8.2"), "8.2.35")
        os.symlink(os.path.join(self.dir, "php8.2"), os.path.join(self.dir, "php"))
        self.assertEqual(len(self.scan()[1]["findings"]), 1)


class ImagesCommand(unittest.TestCase):
    def test_exit_codes_and_sarif(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "Dockerfile"), "w") as fh:
                fh.write("FROM php:8.3.35-apache\n")
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                code, out = cli("images", "--format", "sarif")
                self.assertEqual(code, 1)
                sarif = json.loads(out)
                result = sarif["runs"][0]["results"][0]
                self.assertEqual(result["level"], "error")
                loc = result["locations"][0]["physicalLocation"]
                self.assertEqual(loc["artifactLocation"]["uri"], "Dockerfile")
                self.assertEqual(loc["region"]["startLine"], 1)
                code, _ = cli("images", "--image", "php:8.5.12")
                self.assertEqual(code, 0)
            finally:
                os.chdir(cwd)

    def test_image_flag_does_not_scan_cwd(self):
        code, out = cli("images", "--image", "php:8.5.12", "--format", "json")
        self.assertEqual(len(json.loads(out)["findings"]), 1)

    def test_csv_has_header_and_rows(self):
        code, out = cli("images", "--image", "php:7.4-fpm", "--format", "csv")
        lines = out.strip().splitlines()
        self.assertTrue(lines[0].startswith("host,advisory,status"))
        self.assertIn("VULNERABLE", lines[1])


class FleetCommand(unittest.TestCase):
    def test_fleet_pipes_script_over_fake_ssh(self):
        with tempfile.TemporaryDirectory() as tmp:
            bindir = os.path.join(tmp, "bin")
            os.makedirs(bindir)
            # A stand-in for ssh: drop options and the host, run the remote command locally.
            write_exec(os.path.join(bindir, "ssh"), """#!/bin/sh
while [ "$1" != "--" ]; do shift; done
shift; host="$1"; shift
[ "$host" = "down.example" ] && { echo "ssh: connect to host down.example: Connection refused" >&2; exit 255; }
exec sh -c "$*"
""")
            phpdir = os.path.join(tmp, "php")
            os.makedirs(phpdir)
            fake_php(os.path.join(phpdir, "php"), "8.3.30")
            hosts = os.path.join(tmp, "hosts.txt")
            with open(hosts, "w") as fh:
                fh.write("# web tier\nweb1.example\ndown.example  # unreachable\n")
            old_path = os.environ["PATH"]
            os.environ["PATH"] = bindir + os.pathsep + old_path
            try:
                # The fake ssh ignores the host and scans PATH, which now holds our fake php.
                os.environ["PATH"] = bindir + os.pathsep + phpdir + os.pathsep + old_path
                code, out = cli("fleet", hosts, "--format", "json", "--jobs", "2")
            finally:
                os.environ["PATH"] = old_path
        report = json.loads(out)
        by_host = {}
        for f in report["findings"]:
            by_host.setdefault(f["host"], []).append(f)
        self.assertEqual(by_host["web1.example"][0]["status"], pvc.VULNERABLE)
        self.assertEqual(by_host["down.example"][0]["status"], pvc.ERROR)
        self.assertIn("Connection refused", by_host["down.example"][0]["reason"])
        self.assertEqual(code, 1)

    def test_hosts_file_rejects_option_injection(self):
        with tempfile.TemporaryDirectory() as tmp:
            hosts = os.path.join(tmp, "hosts.txt")
            with open(hosts, "w") as fh:
                fh.write("-oProxyCommand=touch /tmp/pwned\n")
            with self.assertRaises(SystemExit):
                pvc.read_hosts(hosts)


class UrlCommand(unittest.TestCase):
    def test_rejects_non_http_schemes(self):
        with self.assertRaises(SystemExit):
            cli("url", "file:///etc/passwd")

    def test_unreachable_is_an_error_finding(self):
        findings = pvc.check_url("http://127.0.0.1:9/", [ADV], timeout=2)
        self.assertEqual(findings[0]["status"], pvc.ERROR)


class Output(unittest.TestCase):
    def test_text_report_has_summary_and_next_steps(self):
        code, out = cli("images", "--image", "php:8.3.35", "--no-color")
        self.assertIn("VULNERABLE", out)
        self.assertIn("Summary: 1 vulnerable", out)
        self.assertIn("What to do:", out)
        self.assertEqual(code, 1)

    def test_quiet_text_drops_banner_and_advice(self):
        _, out = cli("images", "--image", "php:8.3.35", "-q")
        self.assertNotIn("What to do:", out)
        self.assertNotIn("checking PHP2Shell", out)

    def test_advisories_listing_and_version(self):
        code, out = cli("advisories")
        self.assertEqual(code, 0)
        self.assertIn("CVE-2026-109618", out)
        with self.assertRaises(SystemExit):
            cli("--version")


if __name__ == "__main__":
    unittest.main()
