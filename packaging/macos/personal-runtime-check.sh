#!/bin/sh
# Existing-pair compatibility package only. No publisher/trust gate is changed.
set -eu
personal_fail() { printf '%s\n' "$1" >&2; return 1; }
personal_path() {
    personal_cursor=$1
    while [ "$personal_cursor" != / ]; do
        [ ! -L "$personal_cursor" ] || { personal_fail 'Linked personal installation path rejected.'; return 1; }
        if [ -e "$personal_cursor" ]; then
            personal_mode=$(/usr/bin/stat -f %Lp "$personal_cursor")
            [ "$((0$personal_mode & 022))" -eq 0 ] || { personal_fail 'Installation path is writable by another user.'; return 1; }
        fi
        personal_cursor=${personal_cursor%/*}; [ -n "$personal_cursor" ] || personal_cursor=/
    done
}
personal_file() {
    personal_path "$1" || return 1
    [ -f "$1" ] && [ "$(/usr/bin/stat -f %u "$1")" = "$2" ] &&
        [ "$(/usr/bin/stat -f %l "$1")" = 1 ] || { personal_fail 'Expected an owned regular personal installation file.'; return 1; }
}
personal_hash() { /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'; }
personal_check() {
    personal_home=$1; personal_uid=$2; personal_contract=$3; personal_phase=$4
    personal_agent="$personal_home/.local/libexec/lanpilot-tls/rwn-desktop-agent"
    personal_plist="$personal_home/Library/LaunchAgents/com.lanpilot.desktop-tls.plist"
    personal_file "$personal_plist" "$personal_uid" || return 1
    personal_expected_agent=$(/usr/libexec/PlistBuddy -c 'Print :agent_sha256' "$personal_contract")
    personal_expected_plist=$(/usr/libexec/PlistBuddy -c 'Print :service_sha256' "$personal_contract")
    case "$personal_expected_agent$personal_expected_plist" in *[!0-9a-f]*) personal_fail 'Invalid package contract.'; return 1;; esac
    [ "${#personal_expected_agent}" -eq 64 ] && [ "${#personal_expected_plist}" -eq 64 ] || return 1
    [ "$(personal_hash "$personal_plist")" = "$personal_expected_plist" ] || {
        personal_fail 'This package does not match the existing paired service. Settings were not changed.'; return 1;
    }
    [ "$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$personal_plist")" = "$personal_agent" ] || return 1
    [ "$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:1' "$personal_plist")" = '--stream-visual-tls' ] || return 1
    [ "$(/usr/libexec/PlistBuddy -c 'Print :Label' "$personal_plist")" = 'com.lanpilot.desktop-tls' ] || return 1
    if [ -e "$personal_home/Applications/LanPilot.app" ] || [ -L "$personal_home/Applications/LanPilot.app" ]; then
        personal_fail 'A native LanPilot app is present. Personal compatibility installation will not replace that owner.'; return 1
    fi
    personal_path "$personal_agent" || return 1
    if [ -e "$personal_agent" ] || [ -L "$personal_agent" ]; then
        personal_file "$personal_agent" "$personal_uid" || return 1
        [ "$(personal_hash "$personal_agent")" = "$personal_expected_agent" ] || {
            personal_fail 'The installed runtime differs. This package will not downgrade or replace another version.'; return 1;
        }
    elif [ "$personal_phase" != preinstall ]; then
        personal_fail 'Personal runtime is missing after installation.'; return 1
    fi
}
personal_context() {
    personal_uid=$(/usr/bin/id -u)
    [ "$personal_uid" -ne 0 ] || { personal_fail 'Choose installation for the current user, not root.'; return 1; }
    personal_account=$(/usr/bin/id -un)
    personal_record=$(/usr/bin/dscl /Search -read "/Users/$personal_account" NFSHomeDirectory)
    case "$personal_record" in 'NFSHomeDirectory: '*) personal_home=${personal_record#NFSHomeDirectory: };; *) return 1;; esac
    case "$personal_home" in /Users/*) ;; *) return 1;; esac
    personal_short=${personal_home#/Users/}
    case "$personal_short" in ''|*/*) return 1;; esac
    [ "$(/usr/bin/stat -f %u "$personal_home")" = "$personal_uid" ] || return 1
}
