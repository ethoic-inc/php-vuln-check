# Handoff

## State (2026-10-22): launched, then moved to the ethoic-inc org
- The repo was transferred from `jake-bowser` to the `ethoic-inc` GitHub organization the same day (before any posts or stars) and released as v0.1.1; v0.1.2 followed the same day with primary-source advisories, the code of conduct and more tests. Old repo and download URLs redirect; the old Pages URL does not. Copyright holder is Ethoic Inc (see `LICENSE`).
- v0.1.2 is the latest release and is public: https://github.com/ethoic-inc/php-vuln-check, with the single-file download, wheel, sdist and SHA256SUMS attached, and the landing page on GitHub Pages (`site/`, deployed by `pages.yml`).
- Code: `php_vuln_check.py` (scan, images, url, fleet, advisories), 95 unit tests (including an invariant test that PATCHED never appears without evidence), an 18-leg real-distro CI matrix, a GitHub Action (`action.yml`, self-tested in CI), a pre-commit hook, README written for search.
- **Real-distro results** (CI `Real distros` workflow): run against real PHP packages on Debian 12 and 13, Ubuntu 20.04, 22.04 and 24.04, AlmaLinux 8 and 9, Rocky 9, Fedora, Amazon Linux, Alpine and the official `php` images. Exec, default and `--no-exec` modes agree on versions; package ownership, mod_php detection and the vendor-changelog backport check work (AlmaLinux 8's PHP 7.2.24 is correctly PATCHED through a vendor backport naming both CVEs). Unit tests pass on Python 3.6, 3.7 and 3.8 to 3.13. Debian 11 is a best-effort leg (end-of-life, packages moved to the archive).
- **Independent security review** before release (verdict BLOCK: 2 high, 8 medium). Every finding was fixed with regression tests; the rules that came out of it are in `AGENTS.md`.
- Not verified: Windows, SUSE and Arch, Helm values files, PHP in custom prefixes (use `--path`), a real `kubectl` cluster (the parser and command are tested with a fake `kubectl`).
- Fixed versions (8.2.35, 8.3.36, 8.4.27, 8.5.12) are confirmed against PHP's own advisories (GHSA-w8hw-w9fx-j79w for CVE-2026-109618, GHSA-6wmf-4rv5-p3rp for CVE-2026-109619) and, as of 2026-10-22, match the newest official `php` Docker images per branch. Those advisories cover 8.2 to 8.5 only; the 5.4 start of the affected range is Sansec's claim, which is why `min_affected` carries a comment saying so.

## Repository settings (set up at launch)
- Security: secret scanning with push protection, Dependabot alerts and security updates, CodeQL default setup (Python and Actions; the first Python analysis found 0 issues), private vulnerability reporting, and `main` cannot be force-pushed or deleted.
- Community: Discussions with a welcome announcement, issue templates (Wrong detection, Feature request, Question), `SUPPORT.md`, three starter issues.
- Workflows: `ci.yml`, `distros.yml` (18 real-distro legs, skipped for docs-only changes), `pages.yml`, `release.yml` (tag push publishes; run it by hand for a dry run), Dependabot grouped weekly.
- The org profile page lives in the separate public repo `ethoic-inc/.github` (`profile/README.md`, wording taken from ethoic.com).

## Branch claude/vendor-fixed-versions (2026-10-22, not merged or released)
- `scan` uses `vendor_fixed` (fixed distro builds from vendor notices; Ubuntu USN-8948-1 so far) when the dpkg changelog is missing, e.g. in Docker's ubuntu images. Same build line only, compared with `dpkg --compare-versions`. Add new USN builds there as Ubuntu ships them (20.04 / PHP 7.4 is not in USN-8948-1).
- `scan` reads PHP-FPM pool `php_value` / `php_admin_value` overrides from the conventional `php-fpm.conf` and includes; reports `fatal_error_backtraces`. Mitigations reordered to PHP's advisory order.
- New CI leg `ubuntu-24.04 without package docs` (must be PATCHED and show a pool override). Not run locally: no Docker on the Mac mini.
- Release (v0.1.3) is Jake's call after the PR merges.

## Next
1. Watch Issues and Discussions; wrong-detection reports (label `detection`) are the best signal.
2. Add the next PHP advisory as one dict in `ADVISORIES` (see CONTRIBUTING.md).
3. Starter issues: Windows (#2), SUSE/Arch/Alpine changelogs (#3), next advisory (#4).
4. Optional publishing: PyPI (register a trusted publisher for `release.yml`, then set repository variable `PYPI_PUBLISH=true`); GitHub Marketplace listing for the Action.
5. By hand only: upload `site/social-preview.png` (Settings > General > Social preview, GitHub has no API for it) and turn on the two-factor requirement for the `ethoic-inc` org.

## Decisions
- Name is generic (`php-vuln-check`) so the repo outlives this CVE; PHP2Shell keywords live in the description, topics, README and site.
- No active probing. Active scanners already exist (Assetnote and others) and force PHP out of memory on the target.
- Third-party Actions are pinned to commit SHAs; Dependabot sends one grouped weekly PR.
- `distros.yml` skips docs-only changes (`paths-ignore`) so doc edits do not start 18 jobs.
