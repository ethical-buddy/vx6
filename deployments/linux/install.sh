#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  printf 'Usage: sudo ./install.sh LOGIN_USER\n'
  printf 'Install the VX6 Linux bundle, strongSwan dependencies, and the per-user IPsec helper configuration.\n'
}

if [[ ${1:-} == -h || ${1:-} == --help ]]; then
  usage
  exit 0
fi
if [[ ${EUID} -ne 0 ]]; then
  printf 'Run the installer as root, naming the normal user who will run VX6.\n' >&2
  usage >&2
  exit 1
fi
if (( $# != 1 )) || [[ $1 == root ]] || ! getent passwd "$1" >/dev/null; then
  usage >&2
  exit 2
fi

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [[ -f $script_dir/vx6 && -f $script_dir/vx6-ipsecd ]]; then
  bundle_dir=$script_dir
else
  bundle_dir=$(cd "$script_dir/../../dist/linux" && pwd)
fi
for file in vx6 vx6-ipsecd vx6-setup vx6.service vx6-ipsecd.service ipsecd.json.example LICENSE-COMMERCIAL.md; do
  [[ -f $bundle_dir/$file ]] || { printf 'Bundle is incomplete: missing %s\n' "$bundle_dir/$file" >&2; exit 1; }
done

if command -v pacman >/dev/null; then
  pacman -S --needed --noconfirm strongswan nftables
elif command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get -o Dpkg::Options::=--force-confold install -y strongswan strongswan-swanctl nftables
else
  printf 'Unsupported distribution: this bundle currently supports Arch Linux and Debian/Ubuntu.\n' >&2
  exit 1
fi

install -Dm755 "$bundle_dir/vx6" /usr/bin/vx6
install -Dm755 "$bundle_dir/vx6-ipsecd" /usr/bin/vx6-ipsecd
install -Dm755 "$bundle_dir/vx6-setup" /usr/bin/vx6-setup
install -Dm644 "$bundle_dir/vx6.service" /usr/lib/systemd/user/vx6.service
install -Dm644 "$bundle_dir/vx6-ipsecd.service" /usr/lib/systemd/system/vx6-ipsecd.service
install -Dm644 "$bundle_dir/ipsecd.json.example" /etc/vx6/ipsecd.json.example
install -Dm644 "$bundle_dir/LICENSE-COMMERCIAL.md" /usr/share/licenses/vx6/LICENSE-COMMERCIAL.md
if [[ ${VX6_SETUP_NO_SYSTEMD:-0} != 1 ]]; then
  systemctl daemon-reload
fi
VX6_SETUP_NO_SYSTEMD="${VX6_SETUP_NO_SYSTEMD:-0}" vx6-setup "$1"

printf '\nInstall complete. As %s, run `vx6 init --name YOUR_NAME`, then `vx6 doctor`.\n' "$1"
