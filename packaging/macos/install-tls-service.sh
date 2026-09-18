#!/bin/sh
# Consumes a generated plist but NEVER installs its arbitrary launchd keys.
# Reconstructs a fixed, user-session-only job from validated arguments.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
fail() { printf 'tls_service_install=failed reason=%s\n' "$1" >&2; exit 65; }
[ "$(uname -s)" = Darwin ] || fail macos_required
[ "$#" -eq 2 ] || fail expected_check_or_install_and_plist
action=$1
case "$action" in --check|--install) ;; *) fail unknown_action ;; esac
source_plist=$2
case "$source_plist" in /*) ;; *) fail absolute_plist_required ;; esac
[ -f "$source_plist" ] && [ ! -L "$source_plist" ] || fail regular_plist_required
[ "$(stat -f '%z' "$source_plist")" -le 65536 ] || fail plist_too_large
plutil -lint "$source_plist" >/dev/null || fail malformed_plist
argument() { /usr/libexec/PlistBuddy -c "Print :ProgramArguments:$1" "$source_plist"; }
agent=$(argument 0)
[ "$(argument 1)" = --stream-visual-tls ] || fail wrong_endpoint
bind=$(argument 2)
port=$(argument 3)
identity=$(argument 4)
fingerprint=$(argument 5)
root=$(argument 6)
control=$(argument 7)
visual=$(argument 8)
ocsp=$(argument 9)
if argument 10 >/dev/null 2>&1; then fail excess_arguments; fi
case "$port" in ''|0*|*[!0-9]*) fail invalid_port ;; esac
[ "${#port}" -le 5 ] && [ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || fail invalid_port
case "$identity" in ''|*[!0-9a-fA-F]*) fail invalid_identity_reference ;; esac
[ "${#identity}" -le 8192 ] && [ $((${#identity} % 2)) -eq 0 ] || fail invalid_identity_reference
case "$fingerprint" in *[!0-9a-fA-F]*) fail invalid_client_pin ;; esac
[ "${#fingerprint}" -eq 64 ] || fail invalid_client_pin
case "$control" in view-only|interactive) ;; *) fail invalid_control ;; esac
case "$visual" in h264-only|exact-only) ;; *) fail invalid_visual ;; esac
printf '%s\n' "$bind" | awk -F. '
    NF != 4 {exit 1}
    {for(i=1;i<=4;i++) if($i !~ /^[0-9]+$/ || $i>255 || (length($i)>1 && substr($i,1,1)=="0")) exit 1;
     if(!($1==10 || $1==127 || ($1==172 && $2>=16 && $2<=31) || ($1==192 && $2==168))) exit 1;
     count++}
    END {if(count!=1) exit 1}' || fail invalid_lan_bind
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
sh "$script_dir/check-tls-resources.sh" "$HOME" "$agent" "$root" "$ocsp"
uid=$(id -u)
[ "$uid" -ne 0 ] || fail user_session_required
# Checking GUI domain is read-only; SSH alone does not establish a logged-in GUI.
launchctl print "gui/$uid" >/dev/null 2>&1 || fail no_gui_login_session
label=com.lanpilot.desktop-tls
target="$HOME/Library/LaunchAgents/$label.plist"
[ ! -e "$target" ] && [ ! -L "$target" ] || fail existing_job_file
if launchctl print "gui/$uid/$label" >/dev/null 2>&1; then fail existing_loaded_job; fi
check_directory() {
    directory=$1
    [ -d "$directory" ] && [ ! -L "$directory" ] || fail unsafe_install_directory
    [ "$(stat -f '%u' "$directory")" = "$uid" ] || fail wrong_directory_owner
    mode=$(stat -f '%Lp' "$directory")
    [ $((0$mode & 0022)) -eq 0 ] || fail writable_install_directory
    acl=$(ls -lde "$directory")
    if printf '%s\n' "$acl" | grep -Eq '^[[:space:]]*[0-9]+:.* allow '; then fail install_directory_acl; fi
}
check_directory "$HOME/Library"
if [ -e "$HOME/Library/LaunchAgents" ] || [ -L "$HOME/Library/LaunchAgents" ]; then
    check_directory "$HOME/Library/LaunchAgents"
fi
if [ "$action" = --check ]; then
    printf '%s\n' 'tls_service_preflight=passed installed=0 started=0 trust_authenticated=0'
    exit 0
fi
umask 077
if [ ! -d "$HOME/Library/LaunchAgents" ]; then mkdir "$HOME/Library/LaunchAgents"; fi
check_directory "$HOME/Library/LaunchAgents"
temporary=$(mktemp "$HOME/Library/LaunchAgents/.lanpilot-tls.XXXXXX")
trap 'rm -f "$temporary"' EXIT
trap 'exit 130' HUP INT TERM
xml_string() {
    printf '<string>'
    printf '%s' "$1" | sed -e 's/\&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
    printf '</string>\n'
}
{
    printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>' '<plist version="1.0"><dict>'
    printf '%s\n' '<key>Label</key><string>com.lanpilot.desktop-tls</string>' '<key>ProgramArguments</key><array>'
    for value in "$agent" --stream-visual-tls "$bind" "$port" "$identity" "$fingerprint" "$root" "$control" "$visual" "$ocsp"; do xml_string "$value"; done
    printf '%s\n' '</array><key>LimitLoadToSessionType</key><string>Aqua</string>'
    printf '%s\n' '<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>' '<key>ThrottleInterval</key><integer>10</integer><key>Umask</key><integer>63</integer>'
    printf '<key>WorkingDirectory</key>'; xml_string "$HOME"
    printf '%s\n' '<key>StandardOutPath</key><string>/dev/null</string>' '<key>StandardErrorPath</key><string>/dev/null</string>' '</dict></plist>'
} > "$temporary"
plutil -lint "$temporary" >/dev/null || fail generated_plist_invalid
# Atomic create-new: never replace an existing user's job or invoke bootout.
ln "$temporary" "$target" || fail install_target_exists
rm -f "$temporary"
if ! launchctl bootstrap "gui/$uid" "$target"; then
    # Preserve the newly created file for explicit inspection/retry. No broad
    # rollback or kill: another job may have appeared after the preflight.
    printf '%s\n' 'tls_service_install=partial plist_created=1 bootstrap_failed=1' >&2
    exit 70
fi
printf '%s\n' 'tls_service_install=registered authenticated_connection_verified=0'
