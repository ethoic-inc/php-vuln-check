# Contributing

Thanks for helping. The most useful contributions are wrong results on a real system and new advisories.

## Report a wrong result

Open a **Wrong detection** issue and include:

- the output of `php-vuln-check scan --format json` (remove hostnames if you need to);
- your OS and how PHP was installed (distro package, Remi, Ondrej, Docker, compiled);
- what you expected and why, ideally the vendor advisory or changelog line.

## Add an advisory

Advisories are one dict in the `ADVISORIES` list at the top of `php_vuln_check.py`.

1. Copy the `PHP2SHELL` entry. Set `id`, `name`, `cves`, `severity`, `published`.
2. `fixed` maps each supported branch to the first fixed release. **Take these from the PHP project's own advisory**, not from a blog post, and link the advisory in `references`.
3. `min_affected` is the oldest affected release. Branches older than the oldest `fixed` branch are treated as end-of-life and need vendor-backport evidence to count as patched.
4. Add test cases to `tests/test_php_vuln_check.py` (see `VersionLogic`).

## Ground rules

- Standard library only, one file, Python 3.6-compatible. `fleet` streams this file over SSH.
- No exploit or crash-inducing traffic, ever. This tool reads, it does not probe.
- `PATCHED` needs evidence. When unsure, return `REVIEW`.

## Run the tests

```bash
python3 -m unittest discover -s tests -v
```

CI also runs the tool against PHP installed by apt on Ubuntu.
