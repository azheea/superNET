#!/usr/bin/env bash
# Build the superNET iOS app on a Mac with Xcode's command-line tools only
# (no Xcode project): the SwiftUI app plus the PacketTunnel extension, which
# links the Rust core (libsupernet_ffi.a).
#
#   ios/build.sh device      # build/ios/device/superNET.app + superNET.ipa
#   ios/build.sh simulator   # build/ios/simulator/superNET.app (UI only, no tunnel)
#
# Device builds need the Rust library for aarch64-apple-ios:
#   - SUPERNET_LIB=path/to/libsupernet_ffi.a, or
#   - dist/ios/libsupernet_ffi.a (scripts/build-ios-lib.ps1 on Windows), or
#   - cargo on this Mac: IPHONEOS_DEPLOYMENT_TARGET=16.0 cargo build --release --target aarch64-apple-ios -p supernet-ffi
#
# Signing (device): without settings the bundle is signed ad hoc, which checks
# the build but cannot be installed. To install, the Network Extension
# capability needs a paid Apple Developer account:
#   SIGN_IDENTITY="Apple Development: Name (TEAMID)" \
#   APP_PROFILE=app.mobileprovision TUNNEL_PROFILE=tunnel.mobileprovision ios/build.sh device
# (App IDs app.supernet.client and app.supernet.client.tunnel, both with the
# App Group group.app.supernet.client and Network Extensions enabled.)
#
# The simulator cannot run packet tunnels; start the UI there with sample
# status: xcrun simctl launch booted app.supernet.client -SupernetDemo
set -euo pipefail
kind=${1:-device}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
min=16.0
case "$kind" in
    device) sdk=iphoneos; triple=arm64-apple-ios$min; platform=iPhoneOS ;;
    simulator) sdk=iphonesimulator; triple=arm64-apple-ios$min-simulator; platform=iPhoneSimulator ;;
    *) echo "用法：ios/build.sh device|simulator" >&2; exit 2 ;;
esac
out="$root/build/ios/$kind"
app="$out/superNET.app"
rm -rf "$app"
mkdir -p "$app"
swiftc() { xcrun -sdk "$sdk" swiftc -target "$triple" -O "$@"; }

plist() { # src dst
    cp "$1" "$2"
    plutil -replace CFBundleSupportedPlatforms -json "[\"$platform\"]" "$2"
    plutil -replace DTPlatformName -string "$sdk" "$2"
}

echo "== 主程序"
swiftc -module-name superNET -parse-as-library "$here/App/SupernetApp.swift" -o "$app/superNET"
plist "$here/App/Info.plist" "$app/Info.plist"
printf 'APPL????' > "$app/PkgInfo"

if [ "$kind" = device ]; then
    lib=${SUPERNET_LIB:-}
    for c in "$root/dist/ios/libsupernet_ffi.a" "$root/target/aarch64-apple-ios/release/libsupernet_ffi.a"; do
        [ -z "$lib" ] && [ -f "$c" ] && lib=$c
    done
    if [ -z "$lib" ] && command -v cargo >/dev/null; then
        (cd "$root" && IPHONEOS_DEPLOYMENT_TARGET=$min cargo build --release --target aarch64-apple-ios -p supernet-ffi)
        lib="$root/target/aarch64-apple-ios/release/libsupernet_ffi.a"
    fi
    [ -f "${lib:-}" ] || { echo "没有 libsupernet_ffi.a（见本文件开头）" >&2; exit 1; }
    echo "== 隧道扩展（${lib}）"
    ext="$app/PlugIns/PacketTunnel.appex"
    mkdir -p "$ext"
    swiftc -module-name PacketTunnel -parse-as-library -application-extension \
        -import-objc-header "$here/PacketTunnel/PacketTunnel-Bridging-Header.h" \
        "$here/PacketTunnel/PacketTunnelProvider.swift" \
        -L "$(dirname "$lib")" -lsupernet_ffi -lresolv \
        -framework NetworkExtension -framework SystemConfiguration \
        -Xlinker -e -Xlinker _NSExtensionMain \
        -o "$ext/PacketTunnel"
    plist "$here/PacketTunnel/Info.plist" "$ext/Info.plist"
fi

# Entitlements: from the provisioning profile when there is one (it carries
# the team's application identifier), narrowed to what superNET uses.
entitlements() { # profile_or_empty out
    if [ -n "$1" ]; then
        security cms -D -i "$1" > "$out/profile.plist"
        /usr/libexec/PlistBuddy -x -c 'Print :Entitlements' "$out/profile.plist" > "$2"
        /usr/libexec/PlistBuddy -c 'Delete :com.apple.developer.networking.networkextension' "$2" 2>/dev/null || true
        /usr/libexec/PlistBuddy -c 'Add :com.apple.developer.networking.networkextension array' \
            -c 'Add :com.apple.developer.networking.networkextension:0 string packet-tunnel-provider' "$2"
    else
        cp "$here/supernet.entitlements" "$2"
    fi
}

identity=${SIGN_IDENTITY:--}
if [ "$kind" = device ]; then
    entitlements "${TUNNEL_PROFILE:-}" "$out/tunnel.entitlements"
    entitlements "${APP_PROFILE:-}" "$out/app.entitlements"
    [ -n "${TUNNEL_PROFILE:-}" ] && cp "$TUNNEL_PROFILE" "$app/PlugIns/PacketTunnel.appex/embedded.mobileprovision"
    [ -n "${APP_PROFILE:-}" ] && cp "$APP_PROFILE" "$app/embedded.mobileprovision"
    codesign --force --sign "$identity" --entitlements "$out/tunnel.entitlements" --timestamp=none "$app/PlugIns/PacketTunnel.appex"
    codesign --force --sign "$identity" --entitlements "$out/app.entitlements" --timestamp=none "$app"
    (cd "$out" && rm -rf Payload superNET.ipa && mkdir Payload && cp -R superNET.app Payload/ && zip -qry superNET.ipa Payload && rm -rf Payload)
    echo "== 完成：$out/superNET.ipa（签名：${SIGN_IDENTITY:-临时签名，不能安装}）"
else
    codesign --force --sign - --timestamp=none "$app"
    echo "== 完成：$app"
fi
