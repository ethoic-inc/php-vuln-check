# Changelog

## 0.1.0 (unreleased)

First release, built the week PHP2Shell (CVE-2026-109618 / CVE-2026-109619) was disclosed.

- `scan`: finds PHP CLI, FPM, CGI, LiteSpeed and Apache mod_php on a host; reads the version by running `php -n -v` or from the binary; checks Debian/Ubuntu and RHEL-family package changelogs for backports; reports `session.upload_progress.enabled` and `memory_limit`.
- `images`: Dockerfiles (with `ARG` defaults and multi-stage aliases), compose files, Kubernetes manifests, a single `--image`, and running containers with `--docker`.
- `fleet`: runs `scan` on many hosts over SSH without installing anything.
- `url`: reads the advertised `X-Powered-By` version with one GET.
- Output as text, JSON, CSV or SARIF. Exit codes 0/1/2/3.
- GitHub Action for CI gating and code scanning.
