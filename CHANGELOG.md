# Changelog

## Unreleased

- `scan`: when a Debian/Ubuntu package changelog is not installed (Docker's `ubuntu` and `debian` images strip `/usr/share/doc`), compare the package with the fixed builds in the vendor notice (`vendor_fixed` in `ADVISORIES`, starting with Ubuntu USN-8948-1). Before, these installs were always REVIEW. A fixed build only counts for the same build line, so Sury or other-release builds are never judged against it.
- `scan`: read PHP-FPM pool overrides (`php_value` / `php_admin_value` for the tracked settings) from the conventional `php-fpm.conf` and its includes, and report `fatal_error_backtraces` (PHP 8.5).
- Mitigations reordered to match PHP's advisory: `memory_limit=-1` in admin config first, then `session.upload_progress.enabled=0` (and `fatal_error_backtraces=0` on 8.5), and the multipart block only for applications that take no uploads.
- CI: an Ubuntu 24.04 run with the image's default of no package docs, which must report the distro PHP as PATCHED and show a pool override.

## 0.1.2 (2026-10-22)

- Fixed versions are now sourced from PHP's own advisories (GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp), which are the first references in the tool, the SARIF output and the docs. The docs say plainly that those advisories cover 8.2 to 8.5 and that the PHP 5.4 start of the affected range comes from Sansec.
- Copyright holder is Ethoic Inc (LICENSE, package metadata, site metadata).
- Code of conduct, an rpm ownership test and an invariant test that PATCHED never appears without evidence.
- No change in detection behavior.

## 0.1.1 (2026-10-22)

Moved to the `ethoic-inc` GitHub organization. Project links, attribution ("An open-source project from Ethoic Inc") and the public contact address (hello@ethoic.com) updated; no change in behavior.

## 0.1.0 (2026-10-22)

First release, built the week PHP2Shell (CVE-2026-109618 / CVE-2026-109619) was disclosed.

- `scan`: finds PHP CLI, FPM, CGI, LiteSpeed and Apache mod_php on a host; reads the version by running `php -n -v` or from the binary; checks Debian/Ubuntu and RHEL-family package changelogs for backports; reports `session.upload_progress.enabled` and `memory_limit`.
- `images`: Dockerfiles (global `ARG` defaults, multi-stage aliases, line continuations, `COPY --from=`), compose files, Kubernetes manifests, a single `--image`, running containers with `--docker` and every pod in a cluster with `--kubectl`.
- `fleet`: runs `scan` on many hosts over SSH without installing anything.
- `url`: reads the advertised `X-Powered-By` version with one GET.
- Output as text, JSON, CSV or SARIF. Exit codes 0/1/2/3, where 3 covers errors and bad usage.
- Hardened after an independent security review: no PATCHED from values that can be overridden (build args, digests, third-party images, banners), no execution of untrusted binaries by default, hostile-input limits for files and processes, validated `fleet` output, sanitized text and CSV, and a NONE status so a host without PHP is not counted as patched.
- `scan` notices running processes that still use a replaced PHP file and asks for a restart.
- GitHub Action and pre-commit hook for CI gating and code scanning.
