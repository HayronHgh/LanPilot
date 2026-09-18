#!/bin/sh
set -eu

install_root=${1:-"$HOME/.local/libexec/remoteworkspacenode"}
expected="$HOME/.local/libexec/remoteworkspacenode"
if [ "$install_root" != "$expected" ]; then
    printf 'refusing unexpected install root: %s\n' "$install_root" >&2
    exit 64
fi
if [ -d "$install_root" ]; then
    /bin/rm -rf "$install_root"
fi
printf 'removed=%s\n' "$install_root"
