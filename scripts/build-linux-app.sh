#!/usr/bin/env bash
# Build the superNET app (GUI) for Linux on Debian/Ubuntu: a .deb with the
# app and the headless binary (/usr/bin/supernet-cli), for this machine's
# architecture.
#
#   ./scripts/build-linux-app.sh [--deps]
#
# --deps installs the build dependencies with apt first (sudo). Needs Rust
# (rustup) and Node.js 18+.
#
# TUN mode and the virtual network need root on Linux: the app itself runs as
# the user with a local proxy (and GNOME's system proxy), and shows the sudo
# command for TUN mode, e.g.
#   sudo supernet-cli --profile ~/.local/share/app.supernet.client/profile.yaml --tun
#
# Output: dist/linux/superNET_<version>_<arch>.deb and dist/linux/supernet
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "${1:-}" == --deps ]]; then
    sudo apt-get update
    sudo apt-get install -y build-essential curl wget file pkg-config libssl-dev \
        libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev libxdo-dev
fi

target=${CARGO_TARGET_DIR:-$PWD/target}
cargo build --release -p supernet-cli
cli="$target/release/supernet"

(cd app && npm ci)
# The headless binary goes into the package next to the app's own.
(cd app && npx tauri build --bundles deb --config "{\"bundle\":{\"linux\":{\"deb\":{\"files\":{\"/usr/bin/supernet-cli\":\"$cli\"}}}}}")

mkdir -p dist/linux
cp "$target"/release/bundle/deb/*.deb dist/linux/
cp "$cli" dist/linux/supernet
ls -la dist/linux
