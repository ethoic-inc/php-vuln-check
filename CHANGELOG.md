# Changelog

## 0.1.0 (unreleased)

First release, built the week PHP2Shell (CVE-2026-109618 / CVE-2026-109619) was disclosed.

- `scan`: finds PHP CLI, FPM, CGI, LiteSpeed and Apache mod_php on a host; reads the version by running `php -n -v` or from the binary; checks Debian/Ubuntu and RHEL-family package changelogs for backports; reports `session.upload_progress.enabled` and `memory_limit`.
- `images`: Dockerfiles (global `ARG` defaults, multi-stage aliases, line continuations, `COPY --from=`), compose files, Kubernetes manifests, a single `--image`, running containers with `--docker` and every pod in a cluster with `--kubectl`.
- `fleet`: runs `scan` on many hosts over SSH without installing anything.
- `url`: reads the advertised `X-Powered-By` version with one GET.
- Output as text, JSON, CSV or SARIF. Exit codes 0/1/2/3, where 3 covers errors and bad usage.
- Hardened after an independent security review: no PATCHED from values that can be overridden (build args, digests, third-party images, banners), no execution of untrusted binaries by default, hostile-input limits for files and processes, validated `fleet` output, sanitized text and CSV, and a NONE status so a host without PHP is not counted as patched.
- `scan` notices running processes that still use a replaced PHP file and asks for a restart.
- GitHub Action and pre-commit hook for CI gating and code scanning.
