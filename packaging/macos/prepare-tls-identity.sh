#!/bin/sh
# Stage a local-only private key and public CSR. No import, trust or service change.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
fail() { printf 'tls_identity_prepare=failed reason=%s\n' "$1" >&2; exit 65; }
[ "$(uname -s)" = Darwin ] || fail macos_required
[ "$#" -eq 0 ] || fail unexpected_arguments
uid=$(id -u)
[ "$uid" -ne 0 ] || fail user_required
case "$HOME" in /Users/*) ;; *) fail unexpected_home ;; esac
umask 077
for directory in "$HOME" "$HOME/.local" "$HOME/.local/share" "$HOME/.local/share/lanpilot"; do
    [ ! -L "$directory" ] || fail symlink_directory
    if [ ! -e "$directory" ]; then mkdir "$directory"; fi
    [ -d "$directory" ] && [ "$(stat -f '%u' "$directory")" = "$uid" ] || fail wrong_directory_owner
    mode=$(stat -f '%Lp' "$directory")
    [ $((0$mode & 0022)) -eq 0 ] || fail writable_directory
    acl=$(ls -lde "$directory")
    if printf '%s\n' "$acl" | grep -Eq '^[[:space:]]*[0-9]+:.* allow '; then fail directory_acl; fi
done
directory="$HOME/.local/share/lanpilot/identity-v1"
[ ! -e "$directory" ] && [ ! -L "$directory" ] || fail identity_already_exists
mkdir "$directory"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$directory/server-key.pending.pem" 2>/dev/null
openssl req -new -sha256 -key "$directory/server-key.pending.pem" -subj '/CN=LanPilot Mac Desktop' -out "$directory/server.csr"
openssl req -in "$directory/server.csr" -verify -noout 2>/dev/null
printf '%s\n' 'tls_identity_prepare=complete key_local_only=1 keychain_imported=0 service_started=0'
# Keep the private 0600 staging key until the issued certificate is verified and
# imported non-extractably into Keychain; never SCP this pending key off the Mac.
