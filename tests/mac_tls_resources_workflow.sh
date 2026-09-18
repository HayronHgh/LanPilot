#!/bin/sh
# Isolated filesystem workflow. Never executes the fixture agent or changes trust.
set -eu
[ "$#" -eq 1 ] || exit 64
checker=$1
case "$checker" in /*) ;; *) exit 64 ;; esac
umask 077
fixture=$(mktemp -d "$HOME/.lanpilot-resource-test.XXXXXX")
cleanup() {
    rm -f "$fixture/agent" "$fixture/root" "$fixture/ocsp" "$fixture/alias" "$fixture/link"
    rmdir "$fixture"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
printf '#!/bin/sh\nexit 99\n' > "$fixture/agent"
printf 'root-fixture' > "$fixture/root"
printf 'ocsp-fixture' > "$fixture/ocsp"
chmod 700 "$fixture/agent"
check() { sh "$checker" "$HOME" "$fixture/agent" "$fixture/root" "$fixture/ocsp"; }
reject() {
    reason=$1
    shift
    code=0
    output=$("$@" 2>&1) || code=$?
    [ "$code" -eq 65 ] || { printf 'unexpected_exit=%s\n' "$code"; exit 1; }
    case "$output" in *"reason=$reason"*) ;; *) printf '%s\n' "$output"; exit 1 ;; esac
}
check
chmod 666 "$fixture/root"
reject writable_by_other_users check
chmod 600 "$fixture/root"
chmod 770 "$fixture"
reject writable_by_other_users check
chmod 700 "$fixture"
ln "$fixture/root" "$fixture/link"
reject hardlinked_resource check
rm "$fixture/link"
ln -s "$fixture/root" "$fixture/link"
reject symlink_resource sh "$checker" "$HOME" "$fixture/agent" "$fixture/link" "$fixture/ocsp"
rm "$fixture/link"
ln -s "$fixture" "$fixture/alias"
reject symlink_resource sh "$checker" "$HOME" "$fixture/alias/agent" "$fixture/root" "$fixture/ocsp"
rm "$fixture/alias"
chmod +a 'everyone allow write' "$fixture/root"
reject allow_acl_requires_review check
chmod -N "$fixture/root"
chmod 600 "$fixture/agent"
reject agent_not_executable check
chmod 700 "$fixture/agent"
dd if=/dev/zero of="$fixture/root" bs=65537 count=1 2>/dev/null
reject trust_file_size check
printf root > "$fixture/root"
check
printf '%s\n' 'PASS resource workflow: writable file/parent, hardlink, symlink file/parent, ACL, executable bit, size; agent_executed=0 trust_changed=0'
