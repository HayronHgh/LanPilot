#!/bin/sh
# Read-only deployment preflight; does not execute the supplied agent.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
fail() { printf 'tls_resource_preflight=failed reason=%s\n' "$1" >&2; exit 65; }
[ "$(uname -s)" = Darwin ] || fail macos_required
[ "$#" -eq 4 ] || fail expected_home_agent_root_ocsp
account_home=$1
agent_path=$2
root_path=$3
ocsp_path=$4
account_uid=$(id -u)
[ "$account_uid" -ne 0 ] || fail user_session_required
case "$account_home" in /Users/*) ;; *) fail invalid_home ;; esac
account_name=${account_home#/Users/}
case "$account_name" in ''|.|..|*/*|*[!A-Za-z0-9._-]*) fail invalid_home ;; esac
[ "$account_home" = "$HOME" ] || fail wrong_account_home
[ "$agent_path" != "$root_path" ] && [ "$agent_path" != "$ocsp_path" ] &&
    [ "$root_path" != "$ocsp_path" ] || fail resources_must_differ

check_component() {
    component=$1
    [ ! -L "$component" ] || fail symlink_resource
    [ -e "$component" ] || fail missing_resource
    owner=$(stat -f '%u' "$component")
    case "$component" in
        "$account_home"|"$account_home"/*) [ "$owner" = "$account_uid" ] || fail wrong_owner ;;
        *) [ "$owner" = 0 ] || fail untrusted_ancestor ;;
    esac
    mode=$(stat -f '%Lp' "$component")
    case "$mode" in ''|*[!0-7]*) fail invalid_mode ;; esac
    [ $((0$mode & 0022)) -eq 0 ] || fail writable_by_other_users
    # POSIX bits alone do not describe ACL grants. Conservative first version:
    # reject any allow ACL (even an owner-only grant); deny-only ACLs are safe.
    # No ACLs or modes are changed here.
    acl=$(ls -lde "$component") || fail unreadable_acl
    if printf '%s\n' "$acl" | grep -Eq '^[[:space:]]*[0-9]+:.* allow '; then
        fail allow_acl_requires_review
    fi
}

for resource in "$agent_path" "$root_path" "$ocsp_path"; do
    case "$resource" in "$account_home"/*) ;; *) fail outside_user_home ;; esac
    case "$resource" in *//*|*/./*|*/../*|*/.|*/..|*/) fail noncanonical_path ;; esac
    if printf '%s' "$resource" | LC_ALL=C grep -q '[[:cntrl:]]'; then fail invalid_path_characters; fi
    [ -f "$resource" ] && [ -r "$resource" ] || fail unreadable_regular_file
    [ "$(stat -f '%l' "$resource")" = 1 ] || fail hardlinked_resource
    cursor=$resource
    while :; do
        check_component "$cursor"
        [ "$cursor" != / ] || break
        cursor=${cursor%/*}
        [ -n "$cursor" ] || cursor=/
    done
    size=$(stat -f '%z' "$resource")
    if [ "$resource" = "$agent_path" ]; then
        [ -x "$resource" ] || fail agent_not_executable
        [ "$size" -gt 0 ] && [ "$size" -le 268435456 ] || fail agent_size
    else
        [ "$size" -gt 0 ] && [ "$size" -le 65536 ] || fail trust_file_size
    fi
done
printf '%s\n' 'tls_resource_preflight=passed resources=3 trust_authenticated=0 agent_executed=0 modified=0'
