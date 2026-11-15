#!/bin/sh
# Installer-internal, read-only first-install guard. No launch, grant or migration.
set -eu
reject() { printf '%s\n' "$1" >&2; return 1; }
check_layout() {
    install_home=$1; install_uid=$2
    case "$install_home" in /*) ;; *) reject 'A local user home is required.'; return 1;; esac
    case "$install_home" in /|*'/../'*|*'/./'*) reject 'Invalid user home.'; return 1;; esac
    cursor=$install_home
    while [ "$cursor" != / ]; do
        [ ! -L "$cursor" ] || { reject 'Linked installation ancestors are not supported.'; return 1; }
        cursor=${cursor%/*}; [ -n "$cursor" ] || cursor=/
    done
    [ -d "$install_home" ] && [ "$(/usr/bin/stat -f %u "$install_home")" = "$install_uid" ] || {
        reject 'The installation home must belong to the current user.'; return 1;
    }
    if [ -e "$install_home/Applications" ] || [ -L "$install_home/Applications" ]; then
        [ -d "$install_home/Applications" ] && [ ! -L "$install_home/Applications" ] &&
            [ "$(/usr/bin/stat -f %u "$install_home/Applications")" = "$install_uid" ] || {
                reject 'Applications must be a regular directory owned by this user.'; return 1;
            }
        mode=$(/usr/bin/stat -f %Lp "$install_home/Applications")
        [ "$((0$mode & 022))" -eq 0 ] || { reject 'Applications must not be writable by other users.'; return 1; }
    fi
    if [ -e "$install_home/Applications/LanPilot.app" ] || [ -L "$install_home/Applications/LanPilot.app" ]; then
        reject 'LanPilot is already installed. Open LanPilot to use its verified update flow. This first-install package will not overwrite it.'
        return 1
    fi
}
main() {
    install_uid=$(/usr/bin/id -u)
    [ "$install_uid" -ne 0 ] || { reject 'Install for this user only, not as root.'; return 1; }
    account=$(/usr/bin/id -un)
    record=$(/usr/bin/dscl /Search -read "/Users/$account" NFSHomeDirectory)
    case "$record" in 'NFSHomeDirectory: '*) install_home=${record#NFSHomeDirectory: };; *) reject 'Cannot resolve the current user home.'; return 1;; esac
    case "$install_home" in /Users/*) ;; *) reject 'This build requires a local home under /Users.'; return 1;; esac
    account_home=${install_home#/Users/}
    case "$account_home" in ''|*/*) reject 'This build requires a direct local account home.'; return 1;; esac
    check_layout "$install_home" "$install_uid"
}
main "$@"
