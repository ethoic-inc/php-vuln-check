# php-vuln-check: rules for AI assistants

A zero-dependency Python CLI that finds PHP installs exposed to known PHP vulnerabilities, starting with PHP2Shell (CVE-2026-109618 / CVE-2026-109619). Public repo: `jake-bowser/php-vuln-check`.

## Rules that must hold
- **Single file, standard library only.** `php_vuln_check.py` is piped to remote hosts by `fleet`, so it cannot import anything else. Keep it Python 3.6-compatible (no walrus, no dataclasses, no `capture_output`).
- **Never send exploit or crash-inducing traffic.** No memory-exhaustion probes, no malformed multipart bodies. This tool reads versions, vendor changelogs and config only. That is its difference from the active scanners.
- **Never overclaim.** A result is `PATCHED` only with evidence (version at or above the fix, or a vendor changelog naming every CVE). If it cannot prove it, it is `REVIEW`, never `PATCHED`.
- **Advisory data lives in `ADVISORIES`.** Fixed versions must be checked against the PHP project's own advisory before changing them.
- `fleet` and `url` take untrusted input (host files, URLs): keep the `--` before the ssh host and the http(s)-only URL check.

## Work
- Tests: `python3 -m unittest discover -s tests -v`
- CI also runs the tool against real PHP installed by apt (`real-php` job). Keep it green.
- Start of session: `git pull`, read this file and `docs/HANDOFF.md`. End of session: update `docs/HANDOFF.md`, commit, push.
- Branches: `claude/<topic>` or `codex/<topic>`, merged by PR. Do not push to `main` directly.
