#!/usr/bin/env bash
#
# php2shell-check.sh
# Discovery, verification, remediation and interim mitigation for
# CVE-2026-109618 (RCE via OOM corruption) and CVE-2026-109619 (RCE via stale global state).
#
# Advisory: https://www.php.net/archive/2026.php#2026-10-21-5
#
# Usage:
#   sudo ./php2shell-check.sh                 # discover + verdict (read-only)
#   sudo ./php2shell-check.sh --json          # same, machine-readable
#   sudo ./php2shell-check.sh --fix           # upgrade PHP packages, restart FPM/Apache, re-check
#   sudo ./php2shell-check.sh --mitigate      # apply php.net interim mitigations (pre-patch window)
#   sudo ./php2shell-check.sh --unmitigate    # remove the interim mitigations after patching
#
# Exit codes: 0 all patched, 1 vulnerable or unknown install found, 2 usage/runtime error.

set -euo pipefail

MODE="check"
OUTPUT="table"
for arg in "$@"; do
  case "$arg" in
    --fix)        MODE="fix" ;;
    --mitigate)   MODE="mitigate" ;;
    --unmitigate) MODE="unmitigate" ;;
    --json)       OUTPUT="json" ;;
    -h|--help)    sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

# Upstream fixed versions, php.net 2026-10-21. Vendor tables re-checked 2026-10-22.
FIXED_85="8.5.12"
FIXED_84="8.4.27"
FIXED_83="8.3.36"
FIXED_82="8.2.35"

# Ubuntu fixed package versions, USN-8948-1 / USN-8948-2.
UBUNTU_FIXED_php8_5_stonking="8.5.9-0ubuntu2.1"
UBUNTU_FIXED_php8_5_resolute="8.5.4-0ubuntu1.5"
UBUNTU_FIXED_php8_3="8.3.6-0ubuntu0.24.04.13"
UBUNTU_FIXED_php8_1="8.1.2-1ubuntu2.28"
UBUNTU_FIXED_php7_4="7.4.3-4ubuntu2.29+esm5"
UBUNTU_FIXED_php7_2="7.2.24-0ubuntu0.18.04.17+esm14"
UBUNTU_FIXED_php7_0="7.0.33-0ubuntu0.16.04.16+esm22"
UBUNTU_FIXED_php5="5.5.9+dfsg-1ubuntu4.29+esm18"

# Debian fixed package versions, DSA-6574-1 (trixie) and DLA-4848-1 (bookworm).
DEBIAN_FIXED_php8_4_trixie="8.4.27-1~deb13u1"
DEBIAN_FIXED_php8_2_bookworm="8.2.35-1~deb12u1"

SURY_FIX_DATE="20261021"
MARK_BEGIN="# php2shell-mitigation-begin"
MARK_END="# php2shell-mitigation-end"

RESULTS=()
EXIT_CODE=0

log()  { [ "$OUTPUT" = "json" ] || echo "$*"; }
warn() { echo "WARN: $*" >&2; }

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "run as root (sudo); package and service state is not readable otherwise" >&2
    exit 2
  fi
}

detect_os() {
  . /etc/os-release
  OS_ID="$ID"
  OS_VERSION_ID="${VERSION_ID:-}"
  OS_CODENAME="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"
  if command -v dpkg >/dev/null 2>&1; then PKG_SYSTEM="deb"
  elif command -v rpm >/dev/null 2>&1; then PKG_SYSTEM="rpm"
  else PKG_SYSTEM="none"; fi
}

# ---------- discovery ----------

discover_binaries() {
  local candidates=()
  local p
  for p in php php-fpm php-cgi lsphp frankenphp; do
    command -v "$p" >/dev/null 2>&1 && candidates+=("$(command -v "$p")")
  done
  for p in /usr/bin/php[0-9]* /usr/sbin/php-fpm* /usr/bin/php-cgi[0-9]* \
           /usr/local/bin/php /usr/local/sbin/php-fpm \
           /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm \
           /opt/rh/*/root/usr/bin/php /opt/rh/*/root/usr/sbin/php-fpm \
           /usr/local/lsws/lsphp*/bin/lsphp /usr/local/lsws/lsphp*/bin/php \
           /usr/lib/apache2/modules/libphp*.so /etc/httpd/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so; do
    [ -e "$p" ] && candidates+=("$p")
  done
  local pid exe
  for pid in /proc/[0-9]*; do
    exe=$(readlink "$pid/exe" 2>/dev/null || true)
    case "$exe" in
      *php*|*lsphp*|*frankenphp*) candidates+=("${exe% (deleted)}") ;;
    esac
  done
  printf '%s\n' "${candidates[@]}" | xargs -I{} realpath -e {} 2>/dev/null | sort -u
}

binary_version() {
  local bin="$1"
  local v=""
  case "$bin" in
    *.so) ;;
    *frankenphp*) v=$("$bin" version 2>/dev/null | grep -oE 'PHP [0-9]+\.[0-9]+\.[0-9]+' | head -1 | awk '{print $2}' || true) ;;
    *) v=$("$bin" -n -v 2>/dev/null | head -1 | awk '{print $2}' | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' || true) ;;
  esac
  if [ -z "$v" ]; then
    v=$(grep -aoE 'X-Powered-By: PHP/[0-9]+\.[0-9]+\.[0-9]+' "$bin" 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || true)
  fi
  echo "$v"
}

binary_sapi() {
  local bin="$1"
  case "$bin" in
    *.so) echo "mod_php" ;;
    *php-fpm*) echo "fpm" ;;
    *php-cgi*) echo "cgi" ;;
    *lsphp*) echo "litespeed" ;;
    *frankenphp*) echo "frankenphp" ;;
    *) echo "cli" ;;
  esac
}

package_owner() {
  local bin="$1"
  if [ "$PKG_SYSTEM" = "deb" ]; then
    dpkg -S "$bin" 2>/dev/null | head -1 | cut -d: -f1
  elif [ "$PKG_SYSTEM" = "rpm" ]; then
    rpm -qf --qf '%{NAME}\n' "$bin" 2>/dev/null | grep -v 'not owned' | head -1
  fi
}

package_version() {
  local pkg="$1"
  if [ "$PKG_SYSTEM" = "deb" ]; then
    dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null
  elif [ "$PKG_SYSTEM" = "rpm" ]; then
    rpm -q --qf '%{VERSION}-%{RELEASE}' "$pkg" 2>/dev/null
  fi
}

classify_source() {
  local pkg="$1" pkgver="$2"
  if [ -z "$pkg" ]; then echo "source"; return; fi
  case "$pkgver" in
    *+0~2026*|*+0~2025*|*+0~2024*|*deb.sury.org*|*~deb1[0-9]u*+*) echo "sury" ;;
    *ubuntu*) echo "ubuntu" ;;
    *deb1[0-9]u*) echo "debian" ;;
    *.remi*|*remi*) echo "remi" ;;
    *module+el*|*.el[0-9]*) echo "rhel" ;;
    *) echo "unknown-package" ;;
  esac
}

branch_of() { echo "$1" | cut -d. -f1,2; }

fixed_upstream_for_branch() {
  case "$1" in
    8.5) echo "$FIXED_85" ;;
    8.4) echo "$FIXED_84" ;;
    8.3) echo "$FIXED_83" ;;
    8.2) echo "$FIXED_82" ;;
    *) echo "" ;;
  esac
}

version_ge() {
  [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$2" ]
}

changelog_mentions_cve() {
  local pkg="$1"
  if [ "$PKG_SYSTEM" = "deb" ]; then
    local f
    for f in "/usr/share/doc/$pkg/changelog.Debian.gz" "/usr/share/doc/$pkg/changelog.gz"; do
      [ -f "$f" ] && zgrep -qE 'CVE-2026-10961[89]' "$f" && return 0
    done
    return 1
  elif [ "$PKG_SYSTEM" = "rpm" ]; then
    rpm -q --changelog "$pkg" 2>/dev/null | grep -qE 'CVE-2026-10961[89]|GHSA-w8hw-w9fx-j79w|GHSA-6wmf-4rv5-p3rp'
  else
    return 1
  fi
}

# ---------- verdicts ----------

verdict_ubuntu() {
  local pkg="$1" pkgver="$2"
  if changelog_mentions_cve "$pkg"; then echo "PATCHED|changelog lists CVE-2026-109618/109619"; return; fi
  local fixed=""
  case "$pkg" in
    php8.5*|libapache2-mod-php8.5)
      case "$OS_CODENAME" in
        stonking) fixed="$UBUNTU_FIXED_php8_5_stonking" ;;
        resolute) fixed="$UBUNTU_FIXED_php8_5_resolute" ;;
      esac ;;
    php8.3*|libapache2-mod-php8.3) fixed="$UBUNTU_FIXED_php8_3" ;;
    php8.1*|libapache2-mod-php8.1) fixed="$UBUNTU_FIXED_php8_1" ;;
    php7.4*|libapache2-mod-php7.4) fixed="$UBUNTU_FIXED_php7_4" ;;
    php7.2*|libapache2-mod-php7.2) fixed="$UBUNTU_FIXED_php7_2" ;;
    php7.0*|libapache2-mod-php7.0) fixed="$UBUNTU_FIXED_php7_0" ;;
    php5*|libapache2-mod-php5) fixed="$UBUNTU_FIXED_php5" ;;
  esac
  if [ -z "$fixed" ]; then echo "UNKNOWN|no Ubuntu fixed version known for $pkg on $OS_CODENAME; check USN-8948"; return; fi
  if dpkg --compare-versions "$pkgver" ge "$fixed"; then echo "PATCHED|$pkgver >= $fixed (USN-8948)"
  else echo "VULNERABLE|$pkgver < $fixed (USN-8948); 20.04 and older need Ubuntu Pro ESM"; fi
}

verdict_debian() {
  local pkg="$1" pkgver="$2"
  if changelog_mentions_cve "$pkg"; then echo "PATCHED|changelog lists CVE-2026-109618/109619"; return; fi
  case "$pkg" in
    php8.4*|libapache2-mod-php8.4)
      if dpkg --compare-versions "$pkgver" ge "$DEBIAN_FIXED_php8_4_trixie"; then echo "PATCHED|$pkgver >= $DEBIAN_FIXED_php8_4_trixie (DSA-6574-1)"
      else echo "VULNERABLE|$pkgver < $DEBIAN_FIXED_php8_4_trixie (DSA-6574-1)"; fi ;;
    php8.2*|libapache2-mod-php8.2)
      if dpkg --compare-versions "$pkgver" ge "$DEBIAN_FIXED_php8_2_bookworm"; then echo "PATCHED|$pkgver >= $DEBIAN_FIXED_php8_2_bookworm (DLA-4848-1)"
      else echo "VULNERABLE|$pkgver < $DEBIAN_FIXED_php8_2_bookworm (DLA-4848-1)"; fi ;;
    *) echo "UNKNOWN|no Debian fixed version known for $pkg; check security-tracker.debian.org/tracker/CVE-2026-109618" ;;
  esac
}

verdict_sury() {
  local upstream="$1" pkgver="$2"
  local branch fixed
  branch=$(branch_of "$upstream")
  fixed=$(fixed_upstream_for_branch "$branch")
  if [ -n "$fixed" ]; then
    if version_ge "$upstream" "$fixed"; then echo "PATCHED|$upstream >= $fixed"
    else echo "VULNERABLE|$upstream < $fixed; apt-get update && apt-get install --only-upgrade 'php$branch*'"; fi
    return
  fi
  local builddate
  builddate=$(echo "$pkgver" | grep -oE '~[0-9]{8}' | tr -d '~' | head -1)
  if [ -n "$builddate" ] && [ "$builddate" -ge "$SURY_FIX_DATE" ]; then
    echo "PATCHED|EOL branch $branch, Sury backport build $builddate >= $SURY_FIX_DATE; plan upgrade to 8.4/8.5"
  else
    echo "VULNERABLE|EOL branch $branch, Sury build ${builddate:-unknown} < $SURY_FIX_DATE; upgrade packages, then plan move to 8.4/8.5"
  fi
}

verdict_rpm() {
  local pkg="$1" upstream="$2" source="$3"
  if changelog_mentions_cve "$pkg"; then echo "PATCHED|rpm changelog lists CVE-2026-109618/109619"; return; fi
  local branch fixed
  branch=$(branch_of "$upstream")
  fixed=$(fixed_upstream_for_branch "$branch")
  if [ -n "$fixed" ] && version_ge "$upstream" "$fixed"; then echo "PATCHED|$upstream >= $fixed"; return; fi
  if [ "$source" = "rhel" ]; then
    echo "VULNERABLE|no CVE in rpm changelog; dnf upgrade 'php*' (RHSA-2026:87072 php:8.2 el9, 87079 php:8.3 el9, 87151 php 8.0 el9, 87080 php:7.4 el8, 87070 php el10, 87071 php8.4 el10; el9 php:8.4/php:8.1 and el8 php:8.0/php:8.2 track RHSB-2026-013)"
  else
    echo "VULNERABLE|$upstream < ${fixed:-no upstream fix for $branch}; dnf upgrade 'php*' from Remi (8.1 backport is 8.1.34-6, CVEs in changelog), or move to AppStream"
  fi
}

verdict_source_build() {
  local upstream="$1"
  local branch fixed
  branch=$(branch_of "$upstream")
  fixed=$(fixed_upstream_for_branch "$branch")
  if [ -n "$fixed" ]; then
    if version_ge "$upstream" "$fixed"; then echo "PATCHED|$upstream >= $fixed"
    else echo "VULNERABLE|$upstream < $fixed; rebuild from php.net tarball"; fi
    return
  fi
  case "$branch" in
    8.1|8.0|7.4) echo "UNKNOWN|EOL branch $branch built from source; patched only if built from git branch PHP-$branch-CVE-2026-109618-109619 (verify build date / commit)" ;;
    *) echo "UNFIXABLE|branch $branch has no upstream or backport fix; isolate or take offline, migrate to 8.4/8.5" ;;
  esac
}

# ---------- configuration state ----------

ini_paths_for() {
  local bin="$1" sapi="$2"
  local branch sapidir remi
  branch=$(branch_of "$(binary_version "$bin")")
  if [ -d "/etc/php/$branch" ]; then
    case "$sapi" in
      fpm) sapidir="fpm" ;;
      mod_php) sapidir="apache2" ;;
      cgi) sapidir="cgi" ;;
      *) sapidir="cli" ;;
    esac
    echo "/etc/php/$branch/$sapidir/php.ini /etc/php/$branch/$sapidir/conf.d"
  elif [[ "$bin" == /opt/remi/php*/root/* ]]; then
    remi=$(echo "$bin" | grep -oE 'php[0-9]+' | head -1)
    echo "/etc/opt/remi/$remi/php.ini /etc/opt/remi/$remi/php.d"
  elif [ -f /etc/php.ini ]; then
    echo "/etc/php.ini /etc/php.d"
  else
    echo ""
  fi
}

cli_for() {
  local bin="$1" sapi="$2"
  if [ "$sapi" = "cli" ]; then echo "$bin"; return; fi
  if [[ "$bin" == /opt/remi/php*/root/* ]]; then echo "${bin%%/root/*}/root/usr/bin/php"; return; fi
  local sibling
  sibling="$(dirname "$bin")/../bin/php"
  if [ -x "$sibling" ]; then realpath "$sibling"; return; fi
  command -v php || true
}

INI_PROBE='echo "upload_progress=", ini_get("session.upload_progress.enabled"), " memory_limit=", ini_get("memory_limit"), " post_max_size=", ini_get("post_max_size"), " fatal_error_backtraces=", (ini_get("fatal_error_backtraces") === false ? "n/a" : ini_get("fatal_error_backtraces"));'

effective_ini() {
  local bin="$1" sapi="$2"
  local cli inifile scandir
  cli=$(cli_for "$bin" "$sapi")
  [ -n "$cli" ] && [ -x "$cli" ] || { echo "n/a (no php cli)"; return; }
  read -r inifile scandir <<<"$(ini_paths_for "$bin" "$sapi")"
  if [ -n "$inifile" ] && [ -f "$inifile" ]; then
    PHP_INI_SCAN_DIR="$scandir" "$cli" -c "$inifile" -r "$INI_PROBE" 2>/dev/null || echo "n/a (probe failed)"
  else
    "$cli" -r "$INI_PROBE" 2>/dev/null || echo "n/a (probe failed)"
  fi
}

fpm_pool_dirs() {
  local d
  for d in /etc/php/*/fpm/pool.d /etc/php-fpm.d /opt/remi/php*/root/etc/php-fpm.d /etc/opt/remi/php*/php-fpm.d; do
    [ -d "$d" ] && echo "$d"
  done
}

fpm_pool_overrides() {
  local d
  for d in $(fpm_pool_dirs); do
    grep -HnE '^\s*php_(admin_)?(value|flag)\[(memory_limit|session\.upload_progress\.enabled|post_max_size|fatal_error_backtraces)\]' "$d"/*.conf 2>/dev/null || true
  done
}

apache_mod_php_loaded() {
  if command -v apache2ctl >/dev/null 2>&1; then apache2ctl -M 2>/dev/null | grep -qi php && return 0; fi
  if command -v httpd >/dev/null 2>&1; then httpd -M 2>/dev/null | grep -qi php && return 0; fi
  return 1
}

fpm_units() {
  systemctl list-units --type=service --all --no-legend 2>/dev/null | awk '{print $1}' | grep -E '^php.*fpm.*\.service$' || true
}

stale_php_processes() {
  local pid maps comm
  for pid in /proc/[0-9]*; do
    maps="$pid/maps"
    [ -r "$maps" ] || continue
    if grep -qE '(php|libphp|lsphp)[^ ]* \(deleted\)$' "$maps" 2>/dev/null; then
      comm=$(cat "$pid/comm" 2>/dev/null || echo '?')
      echo "${pid#/proc/}:$comm"
    fi
  done
}

held_packages() {
  if [ "$PKG_SYSTEM" = "deb" ]; then apt-mark showhold 2>/dev/null | grep -E '^(php|libapache2-mod-php)' || true
  elif [ "$PKG_SYSTEM" = "rpm" ]; then dnf versionlock list 2>/dev/null | grep -E 'php' || true; fi
}

docker_php_containers() {
  command -v docker >/dev/null 2>&1 || return 0
  docker ps --format '{{.ID}} {{.Names}} {{.Image}}' 2>/dev/null | while read -r id name image; do
    local v
    v=$(docker exec "$id" php -n -v 2>/dev/null | head -1 | awk '{print $2}' || true)
    [ -n "$v" ] && echo "$name|$image|$v"
  done
}

# ---------- check ----------

check_binary() {
  local bin="$1"
  local upstream sapi pkg pkgver source verdict reason ini
  upstream=$(binary_version "$bin" || true)
  if [ -z "$upstream" ]; then warn "cannot read version from $bin"; return; fi
  sapi=$(binary_sapi "$bin")
  pkg=$(package_owner "$bin" || true)
  pkgver=$(package_version "$pkg" 2>/dev/null || true)
  source=$(classify_source "$pkg" "$pkgver")
  case "$source" in
    ubuntu) IFS='|' read -r verdict reason <<<"$(verdict_ubuntu "$pkg" "$pkgver")" ;;
    debian) IFS='|' read -r verdict reason <<<"$(verdict_debian "$pkg" "$pkgver")" ;;
    sury)   IFS='|' read -r verdict reason <<<"$(verdict_sury "$upstream" "$pkgver")" ;;
    rhel|remi) IFS='|' read -r verdict reason <<<"$(verdict_rpm "$pkg" "$upstream" "$source")" ;;
    source) IFS='|' read -r verdict reason <<<"$(verdict_source_build "$upstream")" ;;
    *)      IFS='|' read -r verdict reason <<<"$(verdict_source_build "$upstream")"; reason="package $pkg ($pkgver) unrecognised source; $reason" ;;
  esac
  ini=$(effective_ini "$bin" "$sapi" || true)
  [ "$verdict" = "PATCHED" ] || EXIT_CODE=1
  RESULTS+=("$bin|$sapi|$upstream|${pkg:-none}|${pkgver:-n/a}|$source|$verdict|$reason|$ini")
}

run_check() {
  RESULTS=()
  EXIT_CODE=0
  local bin
  while read -r bin; do
    [ -n "$bin" ] && check_binary "$bin"
  done < <(discover_binaries)

  local stale pools containers held modphp="no"
  apache_mod_php_loaded && modphp="yes"
  stale=$(stale_php_processes | tr '\n' ' ')
  pools=$(fpm_pool_overrides)
  containers=$(docker_php_containers)
  held=$(held_packages | tr '\n' ' ')
  if [ -n "$held" ]; then warn "held/version-locked PHP packages will NOT upgrade: $held"; fi

  if [ "$OUTPUT" = "json" ]; then
    print_json "$modphp" "$stale" "$pools" "$containers"
  else
    print_table "$modphp" "$stale" "$pools" "$containers"
  fi
}

print_table() {
  local modphp="$1" stale="$2" pools="$3" containers="$4"
  echo "php2shell check  host=$(hostname)  os=$OS_ID $OS_VERSION_ID ($OS_CODENAME)  pkg=$PKG_SYSTEM  date=$(date -u +%FT%TZ)"
  echo "mod_php loaded in Apache: $modphp"
  echo
  printf '%-10s %-9s %-9s %-28s %-32s %-8s %s\n' VERDICT SAPI VERSION PACKAGE PKGVERSION SOURCE BINARY
  local r
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r bin sapi upstream pkg pkgver source verdict reason ini <<<"$r"
    printf '%-10s %-9s %-9s %-28s %-32s %-8s %s\n' "$verdict" "$sapi" "$upstream" "$pkg" "$pkgver" "$source" "$bin"
    printf '           reason: %s\n' "$reason"
    printf '           ini:    %s\n' "$ini"
  done
  echo
  if [ -n "$pools" ]; then echo "FPM pool overrides touching mitigation keys:"; echo "$pools"; echo; fi
  if [ -n "$containers" ]; then
    echo "Docker containers with PHP (check image tag against 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35):"
    echo "$containers" | awk -F'|' '{printf "  %-30s %-40s php %s\n", $1, $2, $3}'
    echo
  fi
  if [ -n "$stale" ]; then
    echo "STALE PROCESSES still mapping deleted PHP objects (old code is still running, restart them): $stale"
    EXIT_CODE=1
    echo
  fi
  echo "Reminder: after any upgrade restart php-fpm, apache2/httpd, queue workers, Horizon, Octane, supervisor-managed PHP."
  echo "Overall: $([ "$EXIT_CODE" -eq 0 ] && echo ALL PATCHED || echo ACTION REQUIRED)"
}

print_json() {
  local modphp="$1" stale="$2" pools="$3" containers="$4"
  local first=1 r
  printf '{"host":"%s","os":"%s %s","codename":"%s","checked_at":"%s","mod_php_loaded":%s,"installs":[' \
    "$(hostname)" "$OS_ID" "$OS_VERSION_ID" "$OS_CODENAME" "$(date -u +%FT%TZ)" "$([ "$modphp" = yes ] && echo true || echo false)"
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r bin sapi upstream pkg pkgver source verdict reason ini <<<"$r"
    [ $first -eq 1 ] || printf ','
    first=0
    printf '{"binary":"%s","sapi":"%s","version":"%s","package":"%s","package_version":"%s","source":"%s","verdict":"%s","reason":"%s","ini":"%s"}' \
      "$bin" "$sapi" "$upstream" "$pkg" "$pkgver" "$source" "$verdict" "${reason//\"/\\\"}" "$ini"
  done
  printf '],"stale_processes":"%s","pool_overrides":"%s","containers":"%s","overall":"%s"}\n' \
    "$stale" "${pools//\"/\\\"}" "${containers//$'\n'/;}" "$([ "$EXIT_CODE" -eq 0 ] && echo PATCHED || echo ACTION_REQUIRED)"
}

# ---------- fix ----------

upgrade_packages_deb() {
  log "apt-get update"
  apt-get update -q
  local pkgs
  pkgs=$(dpkg-query -W -f='${binary:Package} ${db:Status-Status}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null | awk '$2=="installed"{print $1}' | sort -u | tr '\n' ' ')
  log "apt-get install --only-upgrade $pkgs"
  DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade -o Dpkg::Options::="--force-confold" $pkgs
}

upgrade_packages_rpm() {
  log "dnf upgrade 'php*'"
  dnf -y upgrade 'php*'
}

restart_php_services() {
  local u
  for u in $(fpm_units); do
    log "systemctl restart $u"
    systemctl restart "$u"
  done
  if apache_mod_php_loaded; then
    if systemctl list-units --no-legend 2>/dev/null | grep -q '^apache2.service'; then log "systemctl restart apache2"; systemctl restart apache2; fi
    if systemctl list-units --no-legend 2>/dev/null | grep -q '^httpd.service';   then log "systemctl restart httpd";   systemctl restart httpd; fi
  fi
  log "Restart long-running PHP processes yourself: php artisan queue:restart, horizon:terminate, octane:reload, supervisorctl restart all."
}

run_fix() {
  require_root
  case "$PKG_SYSTEM" in
    deb) upgrade_packages_deb ;;
    rpm) upgrade_packages_rpm ;;
    *) echo "no package manager; rebuild PHP from source (8.2-8.5 tarball or PHP-x.y-CVE-2026-109618-109619 branch)" >&2; exit 2 ;;
  esac
  restart_php_services
  log
  log "Re-checking after upgrade:"
  run_check
}

# ---------- mitigate ----------

mitigation_ini_body() {
  cat <<'EOF'
; php2shell interim mitigation, php.net advisory 2026-10-21. Remove after patching.
session.upload_progress.enabled = 0
fatal_error_backtraces = 0
post_max_size = 32M
memory_limit = -1
EOF
}

mitigation_pool_block() {
  cat <<EOF
$MARK_BEGIN
php_admin_value[memory_limit] = -1
php_admin_flag[session.upload_progress.enabled] = off
php_admin_value[post_max_size] = 32M
$MARK_END
EOF
}

mitigation_apache_body() {
  cat <<'EOF'
# php2shell interim mitigation, php.net advisory 2026-10-21. Remove after patching.
<IfModule mod_php.c>
  php_admin_value memory_limit -1
  php_admin_flag session.upload_progress.enabled off
  php_admin_value post_max_size 32M
  php_admin_flag fatal_error_backtraces off
</IfModule>
EOF
}

ini_dropin_targets() {
  local d
  for d in /etc/php/*/fpm/conf.d /etc/php/*/apache2/conf.d /etc/php/*/cgi/conf.d /etc/php.d /opt/remi/php*/root/etc/php.d /etc/opt/remi/php*/php.d; do
    [ -d "$d" ] && echo "$d/99-php2shell-mitigation.ini"
  done
}

apply_mitigations() {
  require_root
  local f d p
  for f in $(ini_dropin_targets); do
    log "write $f"
    mitigation_ini_body > "$f"
  done
  for d in $(fpm_pool_dirs); do
    for p in "$d"/*.conf; do
      [ -f "$p" ] || continue
      grep -q "$MARK_BEGIN" "$p" && continue
      log "append pool overrides to $p"
      cp -a "$p" "$p.pre-php2shell"
      mitigation_pool_block >> "$p"
    done
  done
  if [ -d /etc/apache2/conf-available ]; then
    log "write /etc/apache2/conf-available/php2shell-mitigation.conf"
    mitigation_apache_body > /etc/apache2/conf-available/php2shell-mitigation.conf
    a2enconf -q php2shell-mitigation >/dev/null 2>&1 || true
  fi
  if [ -d /etc/httpd/conf.d ]; then
    log "write /etc/httpd/conf.d/php2shell-mitigation.conf"
    mitigation_apache_body > /etc/httpd/conf.d/php2shell-mitigation.conf
  fi
  restart_php_services
  log
  log "memory_limit=-1 removes the attacker-controllable OOM but also removes per-request memory protection."
  log "Pair it with a cgroup limit: systemctl set-property php8.x-fpm.service MemoryMax=... (or a container limit). Do NOT use RLIMIT_AS/RLIMIT_DATA."
  log "These mitigations are partial. Patch, then run --unmitigate."
}

remove_mitigations() {
  require_root
  local f d p
  for f in $(ini_dropin_targets); do
    [ -f "$f" ] && { log "remove $f"; rm -f "$f"; }
  done
  for d in $(fpm_pool_dirs); do
    for p in "$d"/*.conf; do
      [ -f "$p" ] || continue
      grep -q "$MARK_BEGIN" "$p" || continue
      log "strip pool overrides from $p"
      sed -i "/^$MARK_BEGIN\$/,/^$MARK_END\$/d" "$p"
      rm -f "$p.pre-php2shell"
    done
  done
  if [ -f /etc/apache2/conf-available/php2shell-mitigation.conf ]; then
    a2disconf -q php2shell-mitigation >/dev/null 2>&1 || true
    rm -f /etc/apache2/conf-available/php2shell-mitigation.conf
  fi
  rm -f /etc/httpd/conf.d/php2shell-mitigation.conf
  restart_php_services
}

# ---------- main ----------

detect_os
case "$MODE" in
  check)      run_check ;;
  fix)        run_fix ;;
  mitigate)   apply_mitigations ;;
  unmitigate) remove_mitigations ;;
esac
exit "$EXIT_CODE"
