# php2shell-check

Discovery, verdict and remediation script for **PHP2Shell**: CVE-2026-109618 (RCE via OOM corruption) and CVE-2026-109619 (RCE via stale global state). Both CVSS v4 9.2. Both let an unauthenticated request run code on any server that serves PHP. Every PHP version from 5.4 to 8.5 is affected. Fixed in **8.5.12, 8.4.27, 8.3.36, 8.2.35** (21 Oct 2026). PHP 8.1 and older get no release from php.net, only distribution backports.

One Bash file. No dependencies beyond coreutils and your package manager. Works on Ubuntu, Debian, RHEL, Alma, Rocky, inside Docker images, with PHP from distro repos, the Ondřej Surý PPA, RHEL AppStream, Remi, or built from source.

## Install

```bash
wget -O php2shell-check.sh https://raw.githubusercontent.com/kometsoft/php2shell-check/main/php2shell-check.sh
chmod +x php2shell-check.sh
sudo ./php2shell-check.sh
```

`curl -fsSLO https://raw.githubusercontent.com/kometsoft/php2shell-check/main/php2shell-check.sh` works too. Read the script before running it as root; it is about 600 lines of plain Bash.

Exit codes: `0` everything patched, `1` something vulnerable, unknown, or still running old code, `2` usage or runtime error.

## The whole job in five steps

Do them in this order on every host. Internet-facing hosts first. Apache mod_php and PHP 8.1 or older before everything else.

| # | Step | What it means |
|---|------|---------------|
| 1 | **Find PHP** | Run the script. It lists every PHP binary, its package source, and a verdict. |
| 2 | **Upgrade** | One `apt` or `dnf` command, per package source below. |
| 3 | **Restart** | php-fpm, Apache, queue workers, Horizon, Octane, supervisor. Old code keeps running until you do. |
| 4 | **Verify** | Re-run the script. Every row `PATCHED`, no stale processes. |
| 5 | **Hunt** | Check for web shells and shells spawned by the web user. Rotate secrets on exposed hosts. |

## 1. Find every PHP install

```bash
sudo ./php2shell-check.sh          # table with a verdict per binary
sudo ./php2shell-check.sh --json   # one JSON object per host, for the inventory sheet
```

| Verdict | Meaning |
|---------|---------|
| `PATCHED` | Nothing to upgrade. Still restart if the script reports stale processes. |
| `VULNERABLE` | Go to step 2. The `reason` line tells you the exact command. |
| `UNKNOWN` / `UNFIXABLE` | Source build of 8.1 or older, or PHP 7.3 and below. Take it off the internet, then plan an upgrade. |

Sample output:

```
php2shell check  host=web-01  os=ubuntu 24.04 (noble)  pkg=deb  date=2026-10-21T23:06:24Z
mod_php loaded in Apache: yes

VERDICT    SAPI      VERSION   PACKAGE                      PKGVERSION                       SOURCE   BINARY
PATCHED    cli       8.3.6     php8.3-cli                   8.3.6-0ubuntu0.24.04.13          ubuntu   /usr/bin/php8.3
           reason: changelog lists CVE-2026-109618/109619
           ini:    upload_progress=1 memory_limit=-1 post_max_size=8M fatal_error_backtraces=n/a
PATCHED    mod_php   8.3.6     libapache2-mod-php8.3        8.3.6-0ubuntu0.24.04.13          ubuntu   /usr/lib/apache2/modules/libphp8.3.so
           reason: changelog lists CVE-2026-109618/109619
           ini:    upload_progress=1 memory_limit=128M post_max_size=8M fatal_error_backtraces=n/a
PATCHED    fpm       8.3.6     php8.3-fpm                   8.3.6-0ubuntu0.24.04.13          ubuntu   /usr/sbin/php-fpm8.3
           reason: changelog lists CVE-2026-109618/109619
           ini:    upload_progress=1 memory_limit=128M post_max_size=8M fatal_error_backtraces=n/a

Overall: ALL PATCHED
```

## 2. Upgrade, by package source

The script tells you which one you are on.

### Ubuntu packages (fix available)

Version string stays the same (8.3.6, 8.1.2). Trust the package revision, not `php -v`.

```bash
sudo apt-get update
sudo apt-get install --only-upgrade -y \
  -o Dpkg::Options::="--force-confold" \
  $(dpkg -l 'php*' 'libapache2-mod-php*' | awk '/^ii/{print $2}')
```

| Release | Fixed package |
|---------|---------------|
| 26.04 | php8.5 ≥ `8.5.4-0ubuntu1.5` |
| 24.04 | php8.3 ≥ `8.3.6-0ubuntu0.24.04.13` |
| 22.04 | php8.1 ≥ `8.1.2-1ubuntu2.28` |
| 20.04 and older | Needs Ubuntu Pro (ESM). Without it: no fix, take offline. |

### Ondřej Surý PPA / packages.sury.org (fix available)

Same `apt` command. Version must read 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. For 8.1 and older, the package build date must be 20261021 or later.

```bash
apt-cache policy php8.4-fpm   # Candidate must be the fixed version
# If not yet: the PPA mirror lags. Wait, or switch to packages.sury.org.
```

Ubuntu's unattended-upgrades does **not** cover this PPA. Nothing patched itself overnight.

### RHEL / Alma / Rocky, AppStream modules (partial)

Red Hat shipped php:8.2 and php:8.3 on RHEL 9 and php:7.4 on RHEL 8 on 21 Oct. php:8.4, php:8.1 and RHEL 10 were still pending at time of writing. Alma and Rocky rebuild after Red Hat.

```bash
sudo dnf upgrade 'php*'
rpm -q --changelog php-fpm | grep CVE-2026-10961   # must print at least one line
```

Stream not fixed yet? Apply the interim mitigations below, or move the stream to Remi (`dnf module reset php && dnf module enable php:remi-8.3`), which has 8.2 to 8.5 fixed.

### Remi, or built from source (manual)

Remi: `dnf upgrade 'php*'`, then `php -v` must show the fixed version. Source builds: rebuild from the php.net tarball with your existing configure flags.

```bash
# 8.2 to 8.5: https://www.php.net/downloads.php
# 7.4 / 8.0 / 8.1 only:
git clone --branch PHP-8.1-CVE-2026-109618-109619 https://github.com/php/php-src.git
```

PHP 7.3 or older: no fix exists anywhere. Take it offline and migrate.

### Docker (fix available)

Running containers never patch themselves. Bump the base tag, rebuild, recreate.

```dockerfile
FROM php:8.4.27-fpm    # pin the fixed patch version, not 8.4.26, not 8.4.27RC1
```

```bash
docker build --pull --no-cache -t app:8.4.27 .
docker compose up -d app     # recreates the container = no stale workers
docker exec app php -v       # must print 8.4.27
```

## 3. Restart everything that runs PHP

The upgrade only changes files on disk. Processes started before it still run the vulnerable code.

| What | Command | Note |
|------|---------|------|
| PHP-FPM (Ubuntu) | `sudo systemctl restart php8.3-fpm` | one per installed version |
| PHP-FPM (RHEL) | `sudo systemctl restart php-fpm` | |
| Apache mod_php | `sudo systemctl restart apache2` (or `httpd`) | full restart, graceful is not enough |
| Laravel queues | `for d in /var/www/*/; do [ -f "$d/artisan" ] && (cd "$d" && php artisan queue:restart); done` | loops every app under /var/www |
| Horizon | same loop with `php artisan horizon:terminate` | supervisor brings it back |
| Octane | same loop with `php artisan octane:reload` | or restart the supervisor program |
| Supervisor | `sudo supervisorctl restart all` | |
| Nginx | none | does not embed PHP |

Or let the script do steps 2 and 3 together:

```bash
sudo ./php2shell-check.sh --fix    # apt/dnf upgrade, restart php-fpm and Apache, re-check
```

Queue workers you still restart yourself.

## 4. Verify

```bash
sudo ./php2shell-check.sh                               # every row PATCHED, exit 0
sudo grep -lE 'php.*\(deleted\)$' /proc/[0-9]*/maps     # must print nothing
```

The second command finds processes still holding the old PHP in memory. Any output means something was not restarted.

## 5. Check you were not already hit

Attacks started before the patch existed. Any internet-facing host should get these checks.

```bash
# New or changed PHP files in app, storage and temp dirs since the leak
sudo find /var/www /tmp /dev/shm -name '*.php' -newermt 2026-10-20 2>/dev/null

# OOM fatals and worker crashes (bursts = someone was probing)
grep -hE 'Allowed memory size|exited on signal' /var/log/php*-fpm.log /var/log/php-fpm/*.log 2>/dev/null | wc -l
grep -c 'Allowed memory size' /var/www/*/storage/logs/laravel-2026-10-2*.log

# Package files modified on disk
sudo debsums -c 2>/dev/null || sudo rpm -Va | grep -E '^..5.*\.php$'
```

Anything suspicious: stop, do not "clean it up", escalate. CVE-2026-109619 also leaks worker memory, so rotate the database password and API keys in each `/var/www/<app>/.env` on exposed hosts even if nothing is found.

## Can't patch in the next few hours?

These reduce exposure. They do not make the host safe. Patch anyway, then undo them.

```bash
sudo ./php2shell-check.sh --mitigate     # session.upload_progress.enabled=0, fatal_error_backtraces=0,
                                         # post_max_size=32M, memory_limit=-1 via php_admin_value, restart
sudo ./php2shell-check.sh --unmitigate   # after patching
```

- `memory_limit=-1` removes the attacker's trigger but also the per-request memory cap. Add `systemctl set-property php8.3-fpm.service MemoryMax=2G` so a runaway worker cannot take the box. Never use `RLIMIT_AS` or `RLIMIT_DATA`; they recreate the vulnerable allocation failure.
- Nginx: `client_max_body_size 8m;` and return 413 for `multipart/form-data` on routes that never take uploads.
- Apache mod_php, or PHP 8.1 and older with no package fix: take the vhost offline. CISA, NSA and NCSC all say so.

## What the script does

| Step | Mechanism |
|------|-----------|
| Find binaries | `command -v` for php/php-fpm/php-cgi/lsphp/frankenphp; well-known paths for versioned Debian binaries, Remi/SCL trees, LiteSpeed, mod_php `.so`; every running process whose `/proc/PID/exe` is PHP. |
| Classify SAPI | By binary name; `apache2ctl -M` / `httpd -M` for a loaded php module; `php -v` inside running Docker containers. |
| Package source | `dpkg -S` / `rpm -qf`; version string pattern decides Ubuntu / Debian / Sury / RHEL / Remi / source build. |
| Verdict | Debian family: package changelog mentioning the CVEs is primary (survives backports), `dpkg --compare-versions` fallback. RPM: `rpm -q --changelog`, then upstream version. Sury and source: upstream version against 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12; EOL Sury branches by build date. |
| Configuration | Effective ini for the SAPI's own php.ini and conf.d: `session.upload_progress.enabled`, `memory_limit`, `post_max_size`, `fatal_error_backtraces`; FPM pool `php_admin_value` overrides. |
| Stale processes | Any process mapping a deleted PHP object forces exit 1. |
| Holds | Warns on `apt-mark showhold` / `dnf versionlock`. |
| `--mitigate` / `--unmitigate` | Marked ini drop-ins and pool blocks, Apache conf, restart. Reversible. |
| `--fix` | `apt-get install --only-upgrade --force-confold` on installed php packages, or `dnf upgrade 'php*'`; restart FPM and Apache; re-check. |

Tested in Docker against Ubuntu 24.04 (distro php8.3-fpm + mod_php), Ubuntu 22.04 (php8.1), Rocky Linux 9 (AppStream php:8.2), and the official `php:8.3.35-fpm` / `php:8.3.36-fpm` images.

## Limitations

- Needs root. Inside containers without systemd the restart step is a no-op; recreate the container.
- LiteSpeed and FrankenPHP version detection is best-effort.
- Fixed-version tables are a snapshot of 21 Oct 2026. The changelog check keeps working after later updates; the version-compare fallback would need new numbers.
- It reports. It does not rotate secrets or hunt for web shells.

## Sources

- [php.net security advisory, 21 Oct 2026](https://www.php.net/archive/2026.php#2026-10-21-5)
- [GHSA-w8hw-w9fx-j79w (CVE-2026-109618)](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Ubuntu USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1) · [Debian DSA-6574-1](https://lists.debian.org/debian-security-announce/2026/msg00489.html) · [Red Hat RHSB-2026-013](https://access.redhat.com/security/vulnerabilities/RHSB-2026-013)
- [CISA alert](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching) · [NCSC UK](https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php)
- [Laravel Forge guidance](https://laravel.com/forge/docs/knowledge-base/php-security-release-october-2026)

## License

MIT.
