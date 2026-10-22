# Security policy

## Reporting a vulnerability in php-vuln-check

Please use GitHub's private vulnerability reporting: **Security tab → Report a vulnerability**. Do not open a public issue for anything exploitable.

Of particular interest: command injection through host files or URLs (`fleet`, `url`), unsafe handling of paths given to `--path`, and any case where the tool could be tricked into reporting PATCHED for a vulnerable install.

## Scope

This tool reads versions, changelogs and config. It does not send exploit traffic. Reports about PHP2Shell itself belong with the PHP project.

## Supported versions

Only the latest release receives fixes.
