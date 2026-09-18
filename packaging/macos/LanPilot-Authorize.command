#!/bin/sh
# One-time local setup entry. Does not start desktop capture or networking.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
mode=${1:-interactive}
case "$mode" in interactive|--check) ;; *) printf '%s\n' '不支援的啟動參數。' >&2; exit 64 ;; esac
[ "$#" -le 1 ] || exit 64
if [ "$mode" = interactive ] && { [ ! -t 0 ] || [ ! -t 1 ]; }; then
    printf '%s\n' '請在 Mac 本機雙擊這個入口，或在 Terminal 執行；不會從背景工作要求授權。' >&2
    exit 65
fi
finish() {
    code=$?
    if [ "$mode" = interactive ]; then
        if [ "$code" -ne 0 ]; then printf '\n%s\n' '身份尚未就緒。沒有開啟連線、服務或更改系統根信任。'; fi
        printf '\n%s' '按 Return 關閉。'
        read -r ignored || true
    fi
    exit "$code"
}
trap finish EXIT
agent="$HOME/.local/libexec/lanpilot-tls/rwn-desktop-agent"
receipt="$HOME/.local/share/lanpilot/identity-v1/keychain-reference.txt"
uid=$(id -u)
[ "$uid" -ne 0 ] || exit 65
for file in "$agent" "$receipt"; do
    [ -f "$file" ] && [ -r "$file" ] || { printf '%s\n' 'LanPilot 身份設定或程式尚未安裝。' >&2; exit 65; }
    cursor=$file
    while :; do
        [ ! -L "$cursor" ] && [ "$(stat -f '%u' "$cursor")" = "$uid" ] || exit 65
        permissions=$(stat -f '%Lp' "$cursor")
        [ $((0$permissions & 0022)) -eq 0 ] || exit 65
        acl=$(ls -lde "$cursor")
        if printf '%s\n' "$acl" | grep -Eq '^[[:space:]]*[0-9]+:.* allow '; then exit 65; fi
        [ "$cursor" != "$HOME" ] || break
        cursor=${cursor%/*}
        [ -n "$cursor" ] || exit 65
    done
done
[ -x "$agent" ] || exit 65
[ "$(stat -f '%z' "$receipt")" -le 8193 ] || exit 65
reference=$(cat "$receipt")
case "$reference" in ''|*[!0-9a-fA-F]*) exit 65 ;; esac
[ $((${#reference} % 2)) -eq 0 ] || exit 65
if [ "$mode" = --check ]; then
    "$agent" --check-tls-identity "$reference"
    exit "$?"
fi
printf '%s\n' 'LanPilot 身份授權' '這一步只確認此程式可使用已建立的本機身份，不會開始遠端控制。'
if ! "$agent" --check-tls-identity "$reference" >/dev/null 2>&1; then
    printf '%s\n' '若 macOS 顯示 Keychain 提示，請確認程式為 rwn-desktop-agent，再於本機允許。' '密碼只輸入 macOS 的提示視窗，不要貼給任何人。'
    "$agent" --authorize-tls-identity "$reference"
fi
# A second process must also work without a dialog: one signing success alone
# is not proof that background access was actually persisted.
"$agent" --check-tls-identity "$reference"
printf '\n%s\n' '本機身份已就緒。尚未建立遠端連線；不代表對端驗證或串流已通過。'
