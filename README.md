# php-vuln-check: PHP2Shell checker for servers, Docker images and CI

**A PHP vulnerability checker for [PHP2Shell](https://sansec.io/research/php2shell) (CVE-2026-109618 and CVE-2026-109619).** It tells you which of your servers, Docker images and pipelines still run vulnerable PHP, including the distro-backport cases that version-only checks get wrong. One file, no dependencies, and it never sends exploit traffic.

[![CI](https://github.com/jake-bowser/php-vuln-check/actions/workflows/ci.yml/badge.svg)](https://github.com/jake-bowser/php-vuln-check/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python 3.6+](https://img.shields.io/badge/python-3.6%2B-blue)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen)

## Check your PHP in 10 seconds

```bash
pipx install git+https://github.com/jake-bowser/php-vuln-check
php-vuln-check                 # audit PHP on this server
php-vuln-check images .        # audit Dockerfiles, compose files and Kubernetes manifests
```

No install needed either. It is a single file with no dependencies, so you can drop it on a server:

```bash
curl -fsSLO https://github.com/jake-bowser/php-vuln-check/releases/latest/download/php_vuln_check.py
python3 php_vuln_check.py
```

Each release also publishes `SHA256SUMS` so you can verify the file first. On Python 3.6 hosts this single file is the way to go; `pipx` needs a newer Python.

```text
VULNERABLE  php:7.4-apache
            PHP 7.4
            branch 7.4 is end-of-life with no upstream fix; pulling a newer image on this branch cannot fix it
            at examples/demo/legacy/Dockerfile:2

VULNERABLE  php:8.3.35-fpm-alpine
            PHP 8.3.35
            8.3.35 is below the fixed release 8.3.36
            at examples/demo/app/Dockerfile:3

REVIEW      php:8.3-cli
            PHP 8.3
            floating tag: resolves to the newest 8.3.x at pull time. Pin it to 8.3.36 or later and rebuild with --pull
            at examples/demo/app/docker-compose.yml:5

PATCHED     php:8.4.27-apache
            PHP 8.4.27
            8.4.27 is the fixed release
            at examples/demo/app/docker-compose.yml:3

Summary: 2 vulnerable | 1 need review | 1 patched
```

Try it yourself: `php-vuln-check images examples/demo`.

## What PHP2Shell is, and who is affected

PHP2Shell is a pair of critical remote code execution bugs in the PHP engine itself: **CVE-2026-109618** and **CVE-2026-109619**, both rated CVSS 9.2. They affect unpatched PHP back to 5.4 that serves web requests (Apache `mod_php` and PHP-FPM are the main cases), and need no login. A fatal error such as running out of memory during a `multipart/form-data` request leaves freed memory in use.

| PHP branch | Fixed in | What to do |
|---|---|---|
| 8.5 | **8.5.12** | upgrade |
| 8.4 | **8.4.27** | upgrade |
| 8.3 | **8.3.36** | upgrade |
| 8.2 | **8.2.35** | upgrade |
| 8.1 and older | no upstream release | use a vendor backport, or move to a supported branch |

Details and mitigations: [Sansec](https://sansec.io/research/php2shell), [Help Net Security](https://www.helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619/), [watchTowr](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/). Reports on how widely it is exploited conflict, so patch rather than wait.

## What it checks

| Command | Looks at | Confidence |
|---|---|---|
| `php-vuln-check scan` | every `php`, `php-fpm`, `php-cgi`, `lsphp` and Apache `libphp*.so` on this machine: version, SAPI, owning package, vendor changelog, `session.upload_progress` and `memory_limit` | high |
| `php-vuln-check images PATH` | `FROM` lines in Dockerfiles (with `ARG` defaults), `image:` in compose files and Kubernetes manifests | high for pinned tags |
| `php-vuln-check images --docker` | images of running containers | high for pinned tags |
| `php-vuln-check images --kubectl` | images of every pod in the current cluster (`--kubectl-args "--context prod"`) | high for pinned tags |
| `php-vuln-check fleet hosts.txt` | runs `scan` on every host over SSH, nothing installed there | high |
| `php-vuln-check url https://example.com` | the PHP version a site advertises in `X-Powered-By` (one normal GET). Never says PATCHED: a banner proves nothing | low |

Every result is one of:

- **PATCHED**: version at or above the fix, or the vendor changelog names both CVEs. It describes the files on disk; `scan` downgrades it to REVIEW when running processes still use a replaced PHP file, and you should restart PHP-FPM or Apache after any update.
- **VULNERABLE**: below the fix with no backport evidence, or an end-of-life branch.
- **REVIEW**: it cannot tell (floating image tag, digest-pinned image, hidden version, pre-release, a package whose changelog is not installed). Not a clean bill of health.
- **NONE**: `fleet` found no PHP on that host in the standard locations. This is not PATCHED: PHP in a custom prefix, container or vhost folder would not appear.
- **ERROR**: an SSH, network or file-reading failure. Unreadable or oversized Dockerfiles are errors, never a silent pass.

## Why another PHP2Shell scanner?

Active scanners such as [Assetnote's php2shell-scanner](https://github.com/assetnote/php2shell-scanner) answer "does this host fall over when probed?" by deliberately triggering PHP memory exhaustion on the target. Their authors call that [risky in nature](https://www.helpnetsecurity.com/2026/10/22/php2shell-scanner-tool/). php-vuln-check answers a different question, "what do we run and is it patched?", and does it without touching a running service. Use both.

| | php-vuln-check | Active probe scanners |
|---|---|---|
| Sends crash-inducing requests | never | yes, by design |
| Safe on production | yes | read their warnings |
| Knows about distro backports (Debian, Ubuntu, RHEL family) | yes, via package changelogs | not their job: they test behavior |
| Audits Dockerfiles, compose and Kubernetes | yes | no |
| Audits many hosts at once | yes, `fleet` over SSH | per target |
| CI gate and GitHub code-scanning (SARIF) | yes | no |
| Tests whether a host actually fails when probed | no | yes |

## How backport detection works

Debian, Ubuntu and RHEL patch PHP without bumping it to 8.2.35, so `PHP 8.2.30` on a distro can be safe. For a binary owned by a package, `scan` reads the vendor changelog (`/usr/share/doc/<pkg>/changelog.Debian.gz`, or `rpm -q --changelog`) and treats the host as patched only if **both** CVE IDs are named. You can check by hand:

```bash
zgrep CVE-2026-109618 /usr/share/doc/php8.2-common/changelog.Debian.gz    # Debian, Ubuntu
rpm -q --changelog php-common | grep CVE-2026-109618                       # RHEL, Alma, Rocky
```

If a vendor shipped a fix without naming the CVE, you will see a false `VULNERABLE`. Check the vendor's security advisory, and please open an issue so the lookup can learn that case.

## Run it across your whole estate

```bash
# hosts.txt: one [user@]host per line, # for comments
php-vuln-check fleet hosts.txt --jobs 16 --format csv -o php-exposure.csv
```

The script is streamed over SSH (`python3 -` on the host), so nothing is installed or left behind. You need key-based SSH and Python 3 on each host. Output from the hosts is validated before it is shown. A host where no PHP is found is reported as NONE, not PATCHED.

## Gate your pipeline

```yaml
# .github/workflows/php-check.yml
on: [push, pull_request]
jobs:
  php2shell:
    runs-on: ubuntu-latest
    permissions: { contents: read, security-events: write }
    steps:
      - uses: actions/checkout@v4
      - uses: jake-bowser/php-vuln-check@v0.1.0
        with:
          fail-on: vulnerable          # or "review" to also fail on floating tags
          sarif-file: php-vuln.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: php-vuln.sarif }
```

Findings show up in your repository's Security tab with the Dockerfile line. To block it earlier, add the pre-commit hook:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/jake-bowser/php-vuln-check
    rev: v0.1.0
    hooks:
      - id: php-vuln-check-images
``` Other CI systems: run `php-vuln-check images . --fail-on vulnerable`. Exit codes are `0` clean, `1` vulnerable, `2` needs review, `3` error or bad usage (a mistyped path is an error, not a clean scan). Formats: `--format text|json|csv|sarif`.

## Limits

- It does not test whether a host is exploitable. It tells you whether the PHP on it is patched.
- `images` reads tags in your files. It does not open the image, so a `FROM` line you rebuild later can drift. Pin full versions and rebuild with `--pull`. A version that comes from an `ARG` default or a `${VAR:-default}` can be overridden by a build argument or `.env` file, so it can be VULNERABLE or REVIEW but never PATCHED. Digest-pinned references are REVIEW. Third-party images that merely name themselves `php` are never PATCHED from their tag.
- Directory scans read Dockerfiles (any `Dockerfile*`, `*.Dockerfile`, `Containerfile*`), `COPY --from=` images, and `*.yml`/`*.yaml` files with `image:` entries. JSON manifests are read when you pass them by name. Helm values files that split `repository` and `tag` are not read yet.
- SARIF output includes findings that have a file location (the `images` command), because GitHub code scanning needs one.
- Config findings (`session.upload_progress.enabled`, `memory_limit`) come from `php -i` for that binary. PHP-FPM pool overrides and `.user.ini` files are not visible. They are hints, not proof, and the partial mitigations they relate to do not replace patching.
- `scan` runs `php -n -v` and `php -i` only on binaries that are owned by root (or you) and that neither they nor their parent folders are writable by group or others. Anything else, such as a binary under a tenant's home directory, is read statically and never run. `--no-exec` runs nothing; `--exec` runs everything it finds. Programs are run with no terminal input, a timeout and capped output.
- Linux and macOS hosts. Windows is not supported yet.
- Written for Python 3.6+ so it runs on older enterprise hosts. CI runs the tests on 3.6, 3.7 and 3.8 to 3.13, and runs the tool against real PHP packages on Debian, Ubuntu, AlmaLinux, Rocky, Fedora, Amazon Linux, Alpine and the official PHP images. It is a new tool: read the results critically and report anything that looks wrong.

## FAQ

**Am I vulnerable to PHP2Shell?**
Run `php-vuln-check` on the server. If it prints VULNERABLE, the PHP there is below the fix and has no vendor backport. If you only see PATCHED, the version is fixed or the vendor changelog names both CVEs.

**Which PHP versions fix CVE-2026-109618 and CVE-2026-109619?**
8.2.35, 8.3.36, 8.4.27 and 8.5.12 or later. PHP 8.1 and older have no upstream fix, so you need a vendor backport or an upgrade.

**Is PHP 7.4 or 8.1 vulnerable?**
Yes unless your vendor shipped a backport. Those branches are end-of-life and the PHP project did not release fixes for them.

**Does Ubuntu, Debian or RHEL ship a fixed PHP?**
Often as a backport on an older version number. `scan` checks the package changelog for both CVE IDs, which is why it can say PATCHED for `8.2.30` on a distro.

**How do I check Docker images for PHP2Shell?**
`php-vuln-check images .` reads your Dockerfiles, compose files and Kubernetes manifests. `php-vuln-check images --image php:8.3-fpm` checks one reference, and `--docker` checks running containers.

**Can I scan a website remotely?**
`php-vuln-check url https://example.com` reads the advertised `X-Powered-By` header with one ordinary request. Many sites hide it, a proxy can fake it and backports are invisible from outside, so it only ever reports REVIEW or ERROR. Run `scan` on the server for a real answer.

**Will it crash or slow my server?**
It sends no exploit traffic. `scan` reads files and runs `php -n -v` and `php -i` on trusted binaries only. `--no-exec` skips even that.

**What do I do if it says VULNERABLE?**
Update PHP and restart PHP-FPM or Apache. Until then, blocking `multipart/form-data` at the web server is a partial, temporary mitigation that breaks uploads. See the [Sansec write-up](https://sansec.io/research/php2shell) for exact snippets.

**Does it find other PHP CVEs?**
Not yet. Advisories are one entry in the `ADVISORIES` list at the top of `php_vuln_check.py`, so adding the next one is a small pull request. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Contributing

Wrong result on your distro, a package manager we should read, or the next PHP advisory: open an issue or a pull request. Start with [CONTRIBUTING.md](CONTRIBUTING.md). To report a security problem in this tool, see [SECURITY.md](SECURITY.md).

## Disclaimer

This is an independent project, not affiliated with the PHP Group, Sansec, Assetnote, watchTowr or anyone else named here. It is provided as is under the [MIT license](LICENSE). A PATCHED result is evidence about versions and changelogs, not a guarantee. Only check systems you own or are authorized to check.
