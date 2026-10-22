# Handoff

## State (2026-10-22)
- v0.1.0 built on branch `claude/initial-release`: `php_vuln_check.py` (scan, images, url, fleet, advisories), 41 unit tests, CI with a real-PHP job, GitHub Action (`action.yml`), landing page in `site/`, README written for search.
- Verified: unit tests pass locally (Python 3.9). `images`, `advisories` and the no-PHP path were run by hand.
- **Not yet verified on a real distro**: `scan` against real PHP packages (dpkg/rpm ownership, changelog lookup, `php -i` parsing, libphp static version). The `real-php` CI job exists to prove this on Ubuntu. RHEL-family `rpm` paths have only been tested through fixtures.

## Next
1. Confirm CI is green, especially `real-php`. Fix any parsing differences it exposes.
2. Merge the PR, tag `v0.1.0`, publish the GitHub release (the Action example in the README points at that tag).
3. Go public: description, topics, social preview upload, Pages (`PAGES_ENABLED=true`, Pages source = GitHub Actions). Launch steps are in the project's `SEO and Launch Plan.md` (iCloud › Projects › PHP Vuln Check).
4. Re-check the fixed versions against the PHP project's own advisory; the data currently comes from Sansec, Help Net Security and watchTowr.

## Decisions
- Name is generic (`php-vuln-check`) so the repo outlives this CVE; PHP2Shell keywords live in the description, topics, README and site.
- No active probing. Active scanners already exist (Assetnote and others) and force PHP out of memory on the target.
- License MIT, copyright Jake Bowser. Change if it should sit under Ethoic Inc.
