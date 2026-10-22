import contextlib
import gzip
import http.server
import io
import json
import os
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import php_vuln_check as pvc  # noqa: E402

ADV = pvc.ADVISORIES_BY_ID["PHP2SHELL"]
CVES = set(ADV["cves"])
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0

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


def write(path, text, mode="w"):
    with io.open(path, mode, encoding="utf-8") as fh:
        fh.write(text)


def ev(version, backports=None, **kw):
    return pvc.evaluate(ADV, pvc.parse_version(version), backports, **kw)


def cli(*argv):
    out = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = pvc.main(list(argv))
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue()


class VersionLogic(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(pvc.parse_version("8.2.30"), (8, 2, 30, ""))
        self.assertEqual(pvc.parse_version("8.1.2-1ubuntu2.14"), (8, 1, 2, "-1ubuntu2.14"))
        self.assertIsNone(pvc.parse_version("garbage"))
        self.assertIsNone(pvc.parse_version("8.2." + "9" * 5000))

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

    def test_missing_changelog_is_review_for_packages_and_vulnerable_otherwise(self):
        status, reason = ev("8.2.30", None, packaged=True)
        self.assertEqual(status, pvc.REVIEW)
        self.assertIn("could not be read", reason)
        status, reason = ev("8.2.30", None)
        self.assertEqual(status, pvc.VULNERABLE)
        self.assertIn("not installed from a distro package", reason)
        self.assertNotIn("changelog", ev("8.2.30", None, tail=False)[1])
        self.assertIn("no vendor backport found", ev("8.2.30", set())[1])

    def test_fixed_in_hint(self):
        self.assertEqual(pvc.fixed_in(ADV, "8.3.30"), "8.3.36")
        self.assertIn("no upstream fix", pvc.fixed_in(ADV, "7.4.33"))
        self.assertIn("8.2.35", pvc.fixed_in(ADV, None))
        self.assertIn("8.2.35", pvc.fixed_in(ADV, "x.y"))

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

    def test_static_version_split_across_read_boundary(self):
        # The 8 MiB read boundary falls after "PHP/8.3.3" and before the final "6".
        for cut in (23, 20, 18):
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "libphp.so")
                with open(path, "wb") as fh:
                    fh.write(b"\0" * (8 * 1024 * 1024 - cut) + b"X-Powered-By: PHP/8.3.36\0\0")
                self.assertEqual(pvc.static_version(path), "8.3.36", cut)

    def test_static_version_at_end_of_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "libphp.so")
            with open(path, "wb") as fh:
                fh.write(b"\0" * 100 + b"X-Powered-By: PHP/8.4.27")
            self.assertEqual(pvc.static_version(path), "8.4.27")


class ChangelogEvidence(unittest.TestCase):
    def named(self, text):
        return pvc.cves_named_in(text, ADV["cves"])

    def test_real_fix_lines_count(self):
        text = "php8.2 (8.2.30-1~deb12u2) bookworm-security; urgency=high\n  * Fix CVE-2026-109618 and CVE-2026-109619\n"
        self.assertEqual(self.named(text), CVES)
        self.assertEqual(self.named("- CVE-2026-109618, CVE-2026-109619: use after free"), CVES)

    def test_hostile_or_unrelated_lines_do_not_count(self):
        for text in (
            "* Revert the patch for CVE-2026-109618 and CVE-2026-109619",
            "* Not affected by CVE-2026-109618 or CVE-2026-109619",
            "* TODO: backport CVE-2026-109618, CVE-2026-109619 (pending)",
            "* Unrelated CVE-2026-1096185 and CVE-2026-1096195",
            "* Ignore CVE-2026-109618 CVE-2026-109619 for now",
            "* XCVE-2026-109618 and CVE-2026-1096190",
        ):
            self.assertEqual(self.named(text), set(), text)
        self.assertEqual(self.named("* Revert CVE-2026-109618\n* Fix CVE-2026-109619"), {"CVE-2026-109619"})

    def test_dpkg_changelog_lookup_through_common_package(self):
        owner = {"manager": "dpkg", "name": "php8.2-cli", "version": "8.2.30-1~deb12u2", "source": "php8.2"}
        with tempfile.TemporaryDirectory() as doc:
            os.makedirs(os.path.join(doc, "php8.2-common"))
            with gzip.open(os.path.join(doc, "php8.2-common", "changelog.Debian.gz"), "wt") as fh:
                fh.write("  * Fix CVE-2026-109618 and CVE-2026-109619\n")
            got = pvc.dpkg_changelog(owner, doc_root=doc)
        self.assertEqual(self.named(got), CVES)
        self.assertIsNone(pvc.dpkg_changelog(owner, doc_root="/nonexistent"))

    def test_dpkg_owner_skips_diversion_lines_and_arch_suffix(self):
        out = ("diversion by php-wrapper from: /usr/bin/php\n"
               "diversion by php-wrapper to: /usr/bin/php.real\n"
               "php8.2-cli:amd64: /usr/bin/php.real\n")

        def fake_run(cmd, **kw):
            return (0, out if "-S" in cmd else "8.2.30-1\nphp8.2\n", "")
        with mock.patch.dict(pvc.BIN, {"dpkg": "/bin/sh", "dpkg-query": "/bin/sh"}), \
                mock.patch.object(pvc, "run", fake_run):
            owner = pvc._dpkg_owner("/usr/bin/php")
        self.assertEqual((owner["name"], owner["version"], owner["source"]), ("php8.2-cli", "8.2.30-1", "php8.2"))


class RunHelper(unittest.TestCase):
    def test_no_terminal_input(self):
        code, out, _ = pvc.run(["cat"], timeout=5)
        self.assertEqual((code, out), (0, ""))

    def test_output_is_capped_and_runaway_is_killed(self):
        start = time.time()
        code, out, _ = pvc.run(["yes"], timeout=1, cap=1000)
        self.assertIsNone(code)
        self.assertLessEqual(len(out), 1000)
        self.assertLess(time.time() - start, 6)

    def test_timeout_kills_grandchildren_holding_the_pipes(self):
        start = time.time()
        code, _, _ = pvc.run(["sh", "-c", "sleep 30 & sleep 30"], timeout=1)
        self.assertIsNone(code)
        self.assertLess(time.time() - start, 8)

    def test_missing_command(self):
        self.assertIsNone(pvc.run(["/nonexistent/definitely-not-here"])[0])

    def test_stdin_is_delivered(self):
        self.assertEqual(pvc.run(["cat"], stdin="hello")[1], "hello")


class ImageLogic(unittest.TestCase):
    def verdict(self, ref, derived=False):
        return pvc.evaluate_image(ADV, ref, derived)

    def test_pinned_official_images(self):
        self.assertEqual(self.verdict("php:8.3.36-apache")[0], pvc.PATCHED)
        status, reason, version = self.verdict("php:8.3.35-fpm-alpine")
        self.assertEqual((status, version), (pvc.VULNERABLE, "8.3.35"))
        self.assertNotIn("changelog", reason)
        self.assertNotIn("distro package", reason)

    def test_floating_tags_need_review_unless_eol(self):
        self.assertEqual(self.verdict("php:8.3-apache")[0], pvc.REVIEW)
        self.assertEqual(self.verdict("php:8-cli")[0], pvc.REVIEW)
        self.assertEqual(self.verdict("php:latest")[0], pvc.REVIEW)
        self.assertEqual(self.verdict("php:cli")[0], pvc.REVIEW)
        self.assertEqual(self.verdict("php")[0], pvc.REVIEW)
        self.assertEqual(self.verdict("php:7.4-apache")[0], pvc.VULNERABLE)
        self.assertEqual(self.verdict("php:8.1-fpm")[0], pvc.VULNERABLE)

    def test_registry_prefixes(self):
        self.assertEqual(self.verdict("docker.io/library/php:8.2.35")[0], pvc.PATCHED)

    def test_digest_pins_are_never_trusted_to_the_tag(self):
        self.assertEqual(self.verdict("php@sha256:abcd")[0], pvc.REVIEW)
        for ref in ("php:8.3.36@sha256:abcd", "php:7.4.33@sha256:abcd"):
            status, reason, _ = self.verdict(ref)
            self.assertEqual(status, pvc.REVIEW, ref)
            self.assertIn("digest", reason)

    def test_third_party_images_are_never_patched_from_their_tag(self):
        self.assertEqual(self.verdict("evil/php:8.3.36")[0], pvc.REVIEW)
        self.assertEqual(self.verdict("x/php-nginx:3.7.0")[0], pvc.REVIEW)
        self.assertEqual(self.verdict("registry.local:5000/team/php-fpm:8.4.26")[0], pvc.VULNERABLE)

    def test_bundled_php_images(self):
        status, _, version = self.verdict("wordpress:6.8-php8.3-apache")
        self.assertEqual((status, version), (pvc.REVIEW, "8.3"))
        self.assertEqual(self.verdict("drupal:10-php7.4-apache")[0], pvc.VULNERABLE)

    def test_bundled_prerelease_is_not_patched(self):
        self.assertEqual(self.verdict("wordpress:php8.2.35-rc1")[0], pvc.REVIEW)
        self.assertEqual(self.verdict("wordpress:php8.5.12")[0], pvc.PATCHED)

    def test_values_from_defaults_cannot_make_a_patched_verdict(self):
        status, reason, _ = self.verdict("php:8.5.12-fpm", derived=True)
        self.assertEqual(status, pvc.REVIEW)
        self.assertIn("override", reason)
        status, reason, _ = self.verdict("php:7.4.33-fpm", derived=True)
        self.assertEqual(status, pvc.VULNERABLE)
        self.assertIn("default", reason)

    def test_non_php_images_are_ignored(self):
        for ref in ("nginx:1.25", "phpmyadmin:5.2", "redis", "postgres:16", "node:20-alpine"):
            self.assertIsNone(self.verdict(ref), ref)

    def test_unresolved_variable(self):
        self.assertEqual(self.verdict("php:${TAG}")[0], pvc.REVIEW)
        self.assertIsNone(self.verdict("${BASE}"))

    def test_huge_numbers_do_not_crash(self):
        self.assertEqual(self.verdict("php:" + "9" * 5000 + ".1.1")[0], pvc.REVIEW)


class DockerfileParsing(unittest.TestCase):
    def refs(self, text, name="Dockerfile"):
        with tempfile.TemporaryDirectory() as tmp:
            write(os.path.join(tmp, name), text, "w")
            problems = []
            found = [(r[1], r[2], r[3]) for r in pvc.collect_image_refs([tmp], problems)]
        return found, problems

    def test_arg_substitution_and_stage_aliases(self):
        found, _ = self.refs("ARG PHP_VERSION=8.2.30\nFROM composer:2 AS vendor\n"
                             "FROM php:${PHP_VERSION}-fpm AS app\nFROM app AS test\nFROM scratch\n")
        self.assertEqual(found, [(2, "composer:2", False), (3, "php:8.2.30-fpm", True)])

    def test_stage_local_arg_does_not_override_the_global_one(self):
        found, _ = self.refs("ARG V=7.4.33\nFROM alpine AS base\nARG V=8.5.12\nFROM php:${V}-fpm\n")
        self.assertIn((4, "php:7.4.33-fpm", True), found)

    def test_bom_and_line_continuation(self):
        found, _ = self.refs("﻿FROM php:8.3.35-cli\n")
        self.assertEqual([r[1] for r in found], ["php:8.3.35-cli"])
        found, _ = self.refs("FROM \\\n   php:7.4-apache\n")
        self.assertEqual([(r[0], r[1]) for r in found], [(1, "php:7.4-apache")])

    def test_dockerfile_name_variants_and_comments(self):
        for name in ("Dockerfile-php", "Dockerfile_dev", "Dockerfile.prod", "api.Dockerfile", "Containerfile"):
            found, _ = self.refs("# FROM php:5.6\nFROM php:7.4-fpm\n", name)
            self.assertEqual([r[1] for r in found], ["php:7.4-fpm"], name)

    def test_copy_from_image(self):
        found, _ = self.refs("FROM scratch\nCOPY --from=php:7.4-cli /usr/local/bin/php /php\nCOPY --from=0 /a /b\n")
        self.assertEqual([r[1] for r in found], ["php:7.4-cli"])

    def test_compose_k8s_and_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(os.path.join(tmp, "docker-compose.yml"),
                  "services:\n  web:\n    image: ${PHP_IMAGE:-php:8.3.35-apache}\n  db:\n    image: \"postgres:16\"\n")
            write(os.path.join(tmp, "pod.yaml"), "spec:\n  containers:\n    - image: php:7.4-fpm\n")
            problems = []
            refs = sorted((r[2], r[3]) for r in pvc.collect_image_refs([tmp], problems))
            write(os.path.join(tmp, "pod.json"), '{"spec":{"containers":[{"image":"php:5.6"}]}}')
            explicit = [r[2] for r in pvc.collect_image_refs([os.path.join(tmp, "pod.json")], problems)]
        self.assertEqual(refs, [("php:7.4-fpm", False), ("php:8.3.35-apache", True), ("postgres:16", False)])
        self.assertEqual(explicit, ["php:5.6"])

    def test_pathological_yaml_line_is_fast(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(os.path.join(tmp, "x.yml"), " " * 200000 + "\nimage: php:8.5.12\n")
            start = time.time()
            refs = list(pvc.collect_image_refs([tmp], []))
        self.assertLess(time.time() - start, 3)
        self.assertEqual([r[2] for r in refs], ["php:8.5.12"])

    def test_unreadable_oversized_and_special_files_are_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(os.path.join(tmp, "Dockerfile"), "FROM php:7.4\n" + "#" * (pvc.MAX_TEXT_FILE + 10))
            os.mkdir(os.path.join(tmp, "sub"))
            os.mkfifo(os.path.join(tmp, "sub", "Dockerfile"))
            problems = []
            list(pvc.collect_image_refs([tmp], problems))
            messages = sorted(m for _, m, important in problems if important)
        self.assertEqual(len(messages), 2)
        self.assertTrue(any("larger than" in m for m in messages))
        self.assertTrue(any("not a regular file" in m for m in messages))

    @unittest.skipIf(IS_ROOT, "root can read mode 000 files")
    def test_unreadable_dockerfile_is_an_error_not_a_green_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "Dockerfile")
            write(path, "FROM php:7.4\n")
            os.chmod(path, 0)
            code, out = cli("images", tmp, "--format", "json")
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(out)["findings"][0]["status"], pvc.ERROR)


class ScanWithFakeBinaries(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

    def scan(self, *extra, mode="--exec"):
        code, out = cli("scan", "--no-defaults", "--path", self.dir, "--format", "json", mode, *extra)
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
        code, report = self.scan(mode="--no-exec")
        self.assertFalse(os.path.exists(marker))
        self.assertEqual(report["findings"][0]["status"], pvc.REVIEW)
        self.assertEqual(code, 2)

    def test_default_mode_does_not_run_binaries_in_writable_folders(self):
        marker = os.path.join(self.dir, "ran")
        write_exec(os.path.join(self.dir, "php"), "#!/bin/sh\ntouch '%s'\n" % marker)
        os.chmod(self.dir, 0o777)
        code, out = cli("scan", "--no-defaults", "--path", self.dir, "--format", "json")
        report = json.loads(out)
        self.assertFalse(os.path.exists(marker))
        self.assertIn("--exec", report["findings"][0]["reason"])
        self.assertEqual(code, 2)
        self.scan()  # --exec does run it
        self.assertTrue(os.path.exists(marker))

    def test_exec_and_no_exec_conflict_is_a_usage_error(self):
        code, _ = cli("scan", "--exec", "--no-exec")
        self.assertEqual(code, 3)

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

    def test_missing_path_is_an_error_not_a_clean_scan(self):
        code, _ = cli("scan", "--no-defaults", "--path", os.path.join(self.dir, "typo"))
        self.assertEqual(code, 3)

    def test_duplicate_symlinks_reported_once(self):
        fake_php(os.path.join(self.dir, "php8.2"), "8.2.35")
        os.symlink(os.path.join(self.dir, "php8.2"), os.path.join(self.dir, "php"))
        self.assertEqual(len(self.scan()[1]["findings"]), 1)

    def test_hostile_binary_is_bounded(self):
        write_exec(os.path.join(self.dir, "php"), "#!/bin/sh\nexec yes\n")
        start = time.time()
        code, report = self.scan()
        self.assertEqual(report["findings"][0]["status"], pvc.REVIEW)
        self.assertLess(time.time() - start, 60)

    def test_relative_path_entries_are_ignored(self):
        os.mkdir(os.path.join(self.dir, "rel"))
        fake_php(os.path.join(self.dir, "rel", "php"), "8.2.30")
        cwd = os.getcwd()
        os.chdir(self.dir)
        try:
            with mock.patch.dict(os.environ, {"PATH": "rel"}):
                found = [p for p, _ in pvc.discover([], defaults=True) if p.startswith(os.path.realpath(self.dir))]
        finally:
            os.chdir(cwd)
        self.assertEqual(found, [])


class StaleProcesses(unittest.TestCase):
    def make_proc(self, root, pid, exe, maps=None):
        os.makedirs(os.path.join(root, str(pid)))
        os.symlink(exe, os.path.join(root, str(pid), "exe"))
        if maps is not None:
            write(os.path.join(root, str(pid), "maps"), maps)

    def test_detects_replaced_fpm_binary_and_apache_libphp(self):
        with tempfile.TemporaryDirectory() as root:
            self.make_proc(root, 101, "/usr/sbin/php-fpm8.2 (deleted)")
            self.make_proc(root, 102, "/usr/sbin/apache2",
                           "7f00-7f01 r-xp 00000000 08:01 5 /usr/lib/apache2/modules/libphp8.2.so (deleted)\n"
                           "7f02-7f03 r-xp 00000000 08:01 6 /usr/lib/x86_64-linux-gnu/libc.so.6\n")
            self.make_proc(root, 103, "/usr/sbin/php-fpm8.2")
            os.makedirs(os.path.join(root, "self"))
            stale = pvc.stale_processes(root)
        self.assertEqual(stale[os.path.realpath("/usr/sbin/php-fpm8.2")], [101])
        self.assertEqual(stale[os.path.realpath("/usr/lib/apache2/modules/libphp8.2.so")], [102])

    def test_patched_but_stale_is_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "php")
            fake_php(path, "8.4.27")
            findings = pvc.inspect_target(path, "binary", "always", [ADV], stale={path: [101, 205]})
            clean_run = pvc.inspect_target(path, "binary", "always", [ADV], stale={})
        self.assertEqual(findings[0]["status"], pvc.REVIEW)
        self.assertIn("restart", findings[0]["reason"])
        self.assertIn("101", findings[0]["reason"])
        self.assertEqual(clean_run[0]["status"], pvc.PATCHED)


class ImagesCommand(unittest.TestCase):
    def test_exit_codes_and_sarif(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.mkdir(os.path.join(tmp, "my dir"))
            write(os.path.join(tmp, "my dir", "Dockerfile"), "FROM php:8.3.35-apache\n")
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                code, out = cli("images", "--format", "sarif")
                self.assertEqual(code, 1)
                sarif = json.loads(out)
                rules = [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]]
                self.assertIn("PHP2SHELL/vulnerable", rules)
                self.assertIn("PHP2SHELL/review", rules)
                result = sarif["runs"][0]["results"][0]
                self.assertEqual((result["level"], result["ruleId"]), ("error", "PHP2SHELL/vulnerable"))
                loc = result["locations"][0]["physicalLocation"]
                self.assertEqual(loc["artifactLocation"]["uri"], "my%20dir/Dockerfile")
                self.assertEqual(loc["region"]["startLine"], 1)
                code, _ = cli("images", "--image", "php:8.5.12")
                self.assertEqual(code, 0)
            finally:
                os.chdir(cwd)

    def test_sarif_leaves_out_findings_without_a_file_location(self):
        code, out = cli("images", "--image", "php:7.4-fpm", "--format", "sarif")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["runs"][0]["results"], [])

    def test_image_flag_does_not_scan_cwd(self):
        code, out = cli("images", "--image", "php:8.5.12", "--format", "json")
        self.assertEqual(len(json.loads(out)["findings"]), 1)

    def test_missing_path_is_an_error(self):
        code, _ = cli("images", "/definitely/not/here")
        self.assertEqual(code, 3)

    def test_csv_has_header_rows_and_formula_guard(self):
        code, out = cli("images", "--image", "php:7.4-fpm", "--format", "csv")
        lines = out.strip().splitlines()
        self.assertTrue(lines[0].startswith("host,advisory,status"))
        self.assertIn("VULNERABLE", lines[1])
        report = {"findings": [dict(pvc.make_finding(ADV, "image", "=cmd|' /C calc'!A0", pvc.VULNERABLE, "x"),
                                    location={"file": "-2+3", "line": 1})]}
        csv_text = pvc.render_csv(report)
        self.assertIn("'=cmd", csv_text)
        self.assertIn("'-2+3", csv_text)

    def test_kubectl_images_and_fake_kubectl(self):
        payload = {"items": [
            {"metadata": {"namespace": "web", "name": "a"},
             "spec": {"containers": [{"image": "php:8.3.35-fpm"}, {"image": "nginx:1"}], "initContainers": [{"image": "php:7.4-cli"}]}},
            {"metadata": {"namespace": "web", "name": "b"}, "spec": {"containers": [{"image": "php:8.3.35-fpm"}]}},
            "junk", {"spec": None},
        ]}
        used = pvc.kubectl_images(json.dumps(payload))
        self.assertEqual(sorted(used), ["nginx:1", "php:7.4-cli", "php:8.3.35-fpm"])
        self.assertEqual(sorted(used["php:8.3.35-fpm"]), ["web/a", "web/b"])
        self.assertIsNone(pvc.kubectl_images("not json"))
        with tempfile.TemporaryDirectory() as tmp:
            write_exec(os.path.join(tmp, "kubectl"), "#!/bin/sh\ncat <<'EOF'\n%s\nEOF\n" % json.dumps(payload))
            with mock.patch.dict(os.environ, {"PATH": tmp + os.pathsep + os.environ["PATH"]}):
                code, out = cli("images", "--kubectl", "--format", "json")
        report = json.loads(out)
        self.assertEqual(code, 1)
        by_target = dict((f["target"], f) for f in report["findings"])
        self.assertEqual(by_target["php:8.3.35-fpm"]["status"], pvc.VULNERABLE)
        self.assertIn("web/a", by_target["php:8.3.35-fpm"]["reason"])
        self.assertNotIn("nginx:1", by_target)

    def test_kubectl_failure_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_exec(os.path.join(tmp, "kubectl"), "#!/bin/sh\necho 'no cluster' >&2\nexit 1\n")
            with mock.patch.dict(os.environ, {"PATH": tmp + os.pathsep + os.environ["PATH"]}):
                code, _ = cli("images", "--kubectl")
        self.assertEqual(code, 3)


FAKE_SSH = """#!/bin/sh
while [ "$1" != "--" ]; do shift; done
shift; host="$1"; shift
case "$host" in
  down.example) echo "ssh: connect to host down.example: Connection refused" >&2; exit 255;;
  none.example) printf '{"tool": "php-vuln-check", "findings": [], "notes": ["No PHP"]}\\n'; exit 0;;
  evil.example) printf 'Welcome { banner\\n{"tool": "php-vuln-check", "findings": [{"status": "PATCHED\\\\n::error::x", "target": "\\\\u001b[2Jx", "reason": "r"}, "junk", {"status": "PATCHED", "target": "t", "reason": "ok"}]}\\n'; exit 0;;
esac
exec sh -c "$*"
"""


class FleetCommand(unittest.TestCase):
    def run_fleet(self, hosts_text):
        with tempfile.TemporaryDirectory() as tmp:
            bindir = os.path.join(tmp, "bin")
            os.makedirs(bindir)
            write_exec(os.path.join(bindir, "ssh"), FAKE_SSH)
            phpdir = os.path.join(tmp, "php")
            os.makedirs(phpdir)
            fake_php(os.path.join(phpdir, "php"), "8.3.30")
            hosts = os.path.join(tmp, "hosts.txt")
            write(hosts, hosts_text)
            path = os.pathsep.join([bindir, phpdir, os.environ["PATH"]])
            with mock.patch.dict(os.environ, {"PATH": path}):
                code, out = cli("fleet", hosts, "--exec", "--format", "json", "--jobs", "2")
        by_host = {}
        for f in json.loads(out)["findings"]:
            by_host.setdefault(f["host"], []).append(f)
        return code, by_host

    def test_fleet_pipes_script_over_fake_ssh(self):
        code, by_host = self.run_fleet("# web tier\nweb1.example\ndown.example  # unreachable\n")
        self.assertEqual(by_host["web1.example"][0]["status"], pvc.VULNERABLE)
        self.assertEqual(by_host["down.example"][0]["status"], pvc.ERROR)
        self.assertIn("Connection refused", by_host["down.example"][0]["reason"])
        self.assertEqual(code, 1)

    def test_host_with_no_php_is_not_reported_as_patched(self):
        code, by_host = self.run_fleet("none.example\n")
        (finding,) = by_host["none.example"]
        self.assertEqual(finding["status"], pvc.NONE)
        self.assertEqual(code, 0)

    def test_hostile_remote_output_is_validated(self):
        code, by_host = self.run_fleet("evil.example\n")
        findings = by_host["evil.example"]
        self.assertEqual(sorted(f["status"] for f in findings), [pvc.ERROR, pvc.PATCHED])
        for f in findings:
            self.assertNotIn("\x1b", f["target"])
            self.assertNotIn("\n", f["status"])

    def test_hosts_file_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            hosts = os.path.join(tmp, "hosts.txt")
            for bad in ("-oProxyCommand=touch /tmp/pwned", "host; reboot", "$(whoami)", "a b"):
                write(hosts, bad + "\n")
                with self.assertRaises(pvc.UsageError):
                    pvc.read_hosts(hosts)
            write(hosts, "deploy@web-1.example.com\n10.0.0.5\n::1\n")
            self.assertEqual(pvc.read_hosts(hosts), ["deploy@web-1.example.com", "10.0.0.5", "::1"])
        with self.assertRaises(pvc.UsageError):
            pvc.read_hosts("/nonexistent/hosts.txt")

    def test_extract_report_skips_banners(self):
        good = json.dumps({"tool": "php-vuln-check", "findings": []}, indent=2)
        self.assertIsNotNone(pvc.extract_report("Last login {x}\n{ not json\n" + good))
        self.assertIsNone(pvc.extract_report("{\"tool\": \"other\", \"findings\": []}"))

    def test_validate_finding_rejects_bad_status_and_bounds_strings(self):
        f = pvc.validate_finding({"status": "PATCHED\n::error::x", "target": "t" * 5000, "reason": "a\x1bb"}, "h")
        self.assertEqual(f["status"], pvc.ERROR)
        self.assertLessEqual(len(f["target"]), 500)
        self.assertNotIn("\x1b", f["reason"])
        self.assertIsNone(pvc.validate_finding("junk", "h"))


class UrlCommand(unittest.TestCase):
    def serve(self, handler_cls):
        server = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return "http://127.0.0.1:%d/" % server.server_address[1]

    def test_rejects_non_http_schemes(self):
        code, _ = cli("url", "file:///etc/passwd")
        self.assertEqual(code, 3)

    def test_unreachable_is_an_error_finding(self):
        findings = pvc.check_url("http://127.0.0.1:9/", [ADV], timeout=2)
        self.assertEqual(findings[0]["status"], pvc.ERROR)

    def test_banner_alone_never_says_patched(self):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("X-Powered-By", "PHP/8.5.12")
                self.end_headers()

            def log_message(self, *a):
                pass
        (finding,) = pvc.check_url(self.serve(H), [ADV], timeout=5)
        self.assertEqual(finding["status"], pvc.REVIEW)
        self.assertEqual(finding["version"], "8.5.12")
        self.assertIn("banner cannot prove", finding["reason"])

    def test_lowest_of_several_banners_wins(self):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("X-Powered-By", "PHP/8.5.12")
                self.send_header("X-Powered-By", "PHP/7.4.33")
                self.end_headers()

            def log_message(self, *a):
                pass
        (finding,) = pvc.check_url(self.serve(H), [ADV], timeout=5)
        self.assertEqual((finding["status"], finding["version"]), (pvc.REVIEW, "7.4.33"))
        self.assertIn("end-of-life", finding["reason"])

    def test_no_banner_needs_review(self):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(404)
                self.end_headers()

            def log_message(self, *a):
                pass
        (finding,) = pvc.check_url(self.serve(H), [ADV], timeout=5)
        self.assertEqual(finding["status"], pvc.REVIEW)

    def test_redirect_to_non_http_is_refused(self):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "ftp://127.0.0.1:1/x")
                self.end_headers()

            def log_message(self, *a):
                pass
        (finding,) = pvc.check_url(self.serve(H), [ADV], timeout=5)
        self.assertEqual(finding["status"], pvc.ERROR)
        self.assertIn("non-http", finding["reason"])

    def test_escape_sequences_in_banner_cannot_reach_the_terminal(self):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("X-Powered-By", "PHP/8.3.36\x1b]0;PWNED\x07")
                self.end_headers()

            def log_message(self, *a):
                pass
        findings = pvc.check_url(self.serve(H), [ADV], timeout=5)
        report = pvc.build_report(findings, [], "url")
        text = pvc.render_text(report, [ADV], color=False, quiet=True)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("PWNED", text)


class Output(unittest.TestCase):
    def test_text_report_has_summary_and_next_steps(self):
        code, out = cli("images", "--image", "php:8.3.35", "--no-color")
        self.assertIn("VULNERABLE", out)
        self.assertIn("Summary: 1 vulnerable", out)
        self.assertIn("What to do:", out)
        self.assertEqual(code, 1)

    def test_text_output_is_ascii(self):
        code, out = cli("images", "--image", "php:8.3.35", "--no-color")
        out.encode("ascii")

    def test_quiet_text_drops_banner_and_advice(self):
        _, out = cli("images", "--image", "php:8.3.35", "-q")
        self.assertNotIn("What to do:", out)
        self.assertNotIn("checking PHP2Shell", out)

    def test_patched_text_reminds_to_restart(self):
        _, out = cli("images", "--image", "php:8.5.12")
        self.assertIn("restart PHP-FPM or Apache", out)

    def test_control_characters_in_findings_are_neutralised(self):
        finding = pvc.make_finding(ADV, "image", "php:\x1b]0;PWNED\x07", pvc.VULNERABLE,
                                   "bad\x1b[2Jreason\nmore", version="8.3.35")
        text = pvc.render_text(pvc.build_report([finding], [], "images"), [ADV], color=False, quiet=True)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x07", text)

    def test_ascii_locale_does_not_crash(self):
        stream = io.TextIOWrapper(io.BytesIO(), encoding="ascii")
        with mock.patch.object(sys, "stdout", stream):
            pvc.emit("café · ok\n", None)
            stream.flush()
        self.assertIn(b"ok", stream.buffer.getvalue())

    def test_none_status_is_counted_apart(self):
        f = pvc.make_finding(ADV, "host", "h", pvc.NONE, "nothing")
        report = pvc.build_report([f], [], "fleet")
        self.assertEqual((report["summary"]["none"], report["summary"]["patched"]), (1, 0))
        self.assertIn("1 with no PHP found", pvc.render_text(report, [ADV], False, True))
        self.assertEqual(pvc.exit_code([f], "review"), 0)

    def test_advisories_listing_and_version(self):
        code, out = cli("advisories")
        self.assertEqual(code, 0)
        self.assertIn("CVE-2026-109618", out)
        code, _ = cli("--version")
        self.assertEqual(code, 0)

    def test_usage_errors_exit_3_not_1_or_2(self):
        code, _ = cli("images", "--no-such-flag")
        self.assertEqual(code, 3)
        code, _ = cli("scan", "--advisory", "NOPE")
        self.assertEqual(code, 3)

    def test_internal_errors_exit_3(self):
        with mock.patch.object(pvc, "cmd_scan", side_effect=RuntimeError("boom")):
            code, _ = cli("scan", "--no-defaults")
        self.assertEqual(code, 3)


if __name__ == "__main__":
    unittest.main()
