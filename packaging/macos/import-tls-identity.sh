#!/bin/sh
# Authorized one-time user Keychain import; no system root trust changes.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
fail() { printf 'tls_identity_import=failed reason=%s\n' "$1" >&2; exit 65; }
[ "$#" -eq 2 ] || fail expected_agent_and_probe
agent=$1
probe=$2
case "$agent" in "$HOME/.local/libexec/lanpilot-tls/rwn-desktop-agent") ;; *) fail unexpected_agent ;; esac
case "$probe" in "$HOME"/*) ;; *) fail unexpected_probe ;; esac
[ -x "$agent" ] && [ ! -L "$agent" ] && [ -x "$probe" ] || fail executable_missing
directory="$HOME/.local/share/lanpilot/identity-v1"
key="$directory/server-key.pending.pem"
certificate="$directory/server.pem"
bundle="$directory/identity.pending.p12"
receipt="$directory/keychain-reference.txt"
[ ! -e "$receipt" ] && [ ! -L "$receipt" ] || fail identity_already_imported
[ ! -e "$bundle" ] && [ ! -L "$bundle" ] || fail pending_import_exists
for file in "$key" "$certificate" "$directory/root.der"; do
    [ -f "$file" ] && [ ! -L "$file" ] && [ "$(stat -f '%u' "$file")" = "$(id -u)" ] || fail unsafe_identity_file
    mode=$(stat -f '%Lp' "$file")
    [ $((0$mode & 0022)) -eq 0 ] || fail writable_identity_file
done
umask 077
openssl x509 -inform DER -in "$directory/root.der" -out "$directory/root.pem"
openssl verify -purpose sslserver -CAfile "$directory/root.pem" "$certificate" >/dev/null
key_public=$(openssl rsa -in "$key" -modulus -noout 2>/dev/null)
certificate_public=$(openssl x509 -in "$certificate" -modulus -noout)
[ "$key_public" = "$certificate_public" ] || fail key_certificate_mismatch
fingerprint=$(openssl x509 -in "$certificate" -outform DER | openssl dgst -sha256 | awk '{print $NF}')
# Some native import paths reject empty PKCS12 passphrases. This disposable
# wrapping password is unrelated to the login/CA password; the PFX stays local
# and mode0600. security requires -P for noninteractive import, so the short-lived
# process argument is visible locally; never log it or transfer the PFX.
wrapping=$(openssl rand -hex 24)
printf '%s\n' "$wrapping" | openssl pkcs12 -export -inkey "$key" -in "$certificate" -out "$bundle" -passout stdin -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1
trap 'rm -f "$bundle"' EXIT
trap 'exit 130' HUP INT TERM
security import "$bundle" -k "$HOME/Library/Keychains/login.keychain-db" -f pkcs12 -P "$wrapping" -x -T "$agent"
unset wrapping
reference=$("$probe" identity-ref "$fingerprint")
case "$reference" in keychain_persistent_ref=*) ;; *) fail identity_reference_missing ;; esac
reference=${reference#keychain_persistent_ref=}
case "$reference" in ''|*[!0-9a-fA-F]*) fail invalid_identity_reference ;; esac
# Create-new receipt. The staging PEM remains until actual native TLS signing
# succeeds; never claim a successful import proves Keychain access after login.
(set -C; printf '%s\n' "$reference" > "$receipt")
printf '%s\n' 'tls_identity_import=complete nonextractable_requested=1 system_root_changed=0 native_handshake_verified=0'
