#!/usr/bin/env bash
# Build superNET for macOS on a Mac: the app (superNET.app + .dmg) and the
# headless `supernet` for TUN mode.
#
#   ./scripts/build-macos.sh
#
# Needs: Xcode Command Line Tools (`xcode-select --install`), Rust (rustup),
# Node.js 20+. Builds for the Mac's own architecture; set
# SUPERNET_UNIVERSAL=1 for an Intel + Apple Silicon universal app.
#
# Without a paid Apple account the app is not notarized: the first time,
# right-click superNET.app → Open (or `xattr -dr com.apple.quarantine superNET.app`).
#
# TUN mode needs root on macOS: run the headless binary with sudo, e.g.
#   sudo superNET.app/Contents/MacOS/supernet-cli --profile ~/Library/Application\ Support/app.supernet.client/profile.yaml --tun
# (the app shows this command with the right paths when TUN mode is switched on)
# The app itself runs as a normal user with the system proxy.
set -euo pipefail
cd "$(dirname "$0")/.."

(cd app && npm ci && npm run build)

if [[ "${SUPERNET_UNIVERSAL:-}" == 1 ]]; then
    rustup target add aarch64-apple-darwin x86_64-apple-darwin
    (cd app && npx tauri build --target universal-apple-darwin --bundles app,dmg)
    out=target/universal-apple-darwin/release/bundle
else
    (cd app && npx tauri build --bundles app,dmg)
    out=target/release/bundle
fi

cargo build --release -p supernet-cli

mkdir -p dist/macos
rm -rf dist/macos/superNET.app
cp -R "$out"/macos/superNET.app dist/macos/ 2>/dev/null || true
cp "$out"/dmg/*.dmg dist/macos/ 2>/dev/null || true
cp target/release/supernet dist/macos/
# The headless binary inside the app too: the app shows the sudo command for
# TUN mode with this path (the .dmg above does not have it).
if [ -d dist/macos/superNET.app ]; then
    # Not "supernet": APFS ignores case by default, and that is the app's own superNET.
    cp target/release/supernet dist/macos/superNET.app/Contents/MacOS/supernet-cli
    codesign --force --deep -s - dist/macos/superNET.app
fi
ls -la dist/macos
