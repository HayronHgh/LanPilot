#!/bin/sh
set -eu

source_agent=${1:-}
install_root=${2:-"$HOME/.local/libexec/remoteworkspacenode"}

if [ -z "$source_agent" ]; then
    printf '%s\n' 'usage: install-desktop-preview.sh /absolute/rwn-desktop-agent [absolute-install-root]' >&2
    exit 64
fi
case "$source_agent" in
    /*) ;;
    *) printf '%s\n' 'source agent must be absolute' >&2; exit 64 ;;
esac
case "$install_root" in
    /*) ;;
    *) printf '%s\n' 'install root must be absolute' >&2; exit 64 ;;
esac
case "$install_root" in
    "$HOME/.local/libexec/remoteworkspacenode") ;;
    *) printf '%s\n' 'refusing unexpected install root' >&2; exit 64 ;;
esac
if [ ! -f "$source_agent" ] || [ ! -x "$source_agent" ]; then
    printf '%s\n' 'source agent is missing or not executable' >&2
    exit 66
fi

umask 077
bin_dir="$install_root"
mkdir -p "$bin_dir"
temporary="$bin_dir/rwn-desktop-agent.new"
/usr/bin/install -m 0755 "$source_agent" "$temporary"
/bin/mv -f "$temporary" "$bin_dir/rwn-desktop-agent"

installed="$bin_dir/rwn-desktop-agent"
"$installed" >/dev/null
printf 'installed=%s\n' "$installed"
printf '%s\n' 'startup_model=macOS Remote Login at boot; desktop agent starts on demand inside each authenticated SSH stream'
printf '%s\n' 'verify Remote Login in System Settings > General > Sharing > Remote Login'
