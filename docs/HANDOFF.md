# Handoff

## State (2026-10-22)
- v0.1.0 is built and was beta-tested before release. `php_vuln_check.py` (scan, images, url, fleet, advisories), ~90 unit tests, a 18-leg real-distro CI matrix, GitHub Action (`action.yml`), pre-commit hook, landing page in `site/`, README written for search.
- **Real-distro results** (CI `Real distros` workflow): the tool ran against real PHP packages on Debian 12 and 13, Ubuntu 20.04, 22.04 and 24.04, AlmaLinux 8 and 9, Rocky 9, Fedora, Amazon Linux, Alpine and the official `php` images. Exec, default and `--no-exec` modes agree on versions; package ownership, mod_php detection and the vendor-changelog backport check work (AlmaLinux 8's PHP 7.2.24 is correctly PATCHED through a vendor backport naming both CVEs). The unit tests also pass on Python 3.6, 3.7 and 3.8 to 3.13. Debian 11 is a best-effort leg (end-of-life, packages moved to the archive).
- **Independent security review** (BLOCK verdict before fixes: 2 high, 8 medium) was done and every finding was fixed with regression tests. See the "Harden against independent review findings" commit and `AGENTS.md` for the rules that came out of it.
- Not verified: Windows, SUSE/Arch, Helm values files, PHP in custom prefixes (use `--path`), behavior under a real `kubectl` cluster (the parser and command are tested with a fake `kubectl`).
- Fixed versions (8.2.35, 8.3.36, 8.4.27, 8.5.12) come from Sansec, Help Net Security and watchTowr, and the official `php:8.3` and Alpine `php83` packages also report 8.3.36. Still worth checking against the PHP project's own advisory.

## Launch checklist (see iCloud > Projects > PHP Vuln Check > SEO and Launch Plan.md)
1. Merge PR #1, tag `v0.1.0`, publish the GitHub release (`release.yml` attaches the single-file download, wheel, sdist and `SHA256SUMS`).
2. Make the repo public; set homepage and topics; enable private vulnerability reporting and Discussions.
3. Pages: source = GitHub Actions, set repository variable `PAGES_ENABLED=true`, run `pages.yml`.
4. Upload `site/social-preview.png` in Settings > Social preview (no API).
5. Open the three starter issues (Windows, SUSE/Arch/Alpine changelogs, next PHP advisory).
6. Posting under Jake's name (Hacker News, Reddit, LinkedIn, X, newsletters, awesome-list PRs, dev.to) is left to Jake. Drafts are in the launch plan and the dev.to article draft.
7. Optional: PyPI (needs Jake's account and a trusted-publisher setup, then repository variable `PYPI_PUBLISH=true`); GitHub Marketplace listing (needs Jake to accept the Marketplace terms).

## Decisions
- Name is generic (`php-vuln-check`) so the repo outlives this CVE; PHP2Shell keywords live in the description, topics, README and site.
- No active probing. Active scanners already exist (Assetnote and others) and force PHP out of memory on the target.
- License MIT, copyright Jake Bowser. Change if it should sit under Ethoic Inc.
- Third-party Actions are pinned to commit SHAs; Dependabot keeps them current.
