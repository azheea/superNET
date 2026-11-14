# superNET on iOS

A small native app (SwiftUI) plus a Network Extension packet tunnel that
runs the Rust core. No Xcode project: `ios/build.sh` builds everything with
Xcode's command-line tools.

## Layout

- `App/SupernetApp.swift`: the app.
  - Connect and disconnect.
  - Traffic numbers.
  - The virtual network: this device's address, every peer with its path
    (LAN / IPv6 / public direct / device relay / server relay / down) and its
    latency, and a topology drawn like the desktop one.
  - Settings:
    - invite link, device name, relay on/off;
    - the proxy profile as YAML (the format the other platforms use).
  - Joining makes the device key itself: X25519 via CryptoKit, the same as
    WireGuard.
  - Writes `profile.yaml` into the App Group container (`group.app.supernet.client`).
- `PacketTunnel/PacketTunnelProvider.swift`: the extension.
  1. Joins the virtual network first.
  2. Applies the tunnel settings: 172.19.0.1/30, the mesh address, default
     IPv4/IPv6 routes, and DNS 172.19.0.2 for every domain.
  3. Hands the utun descriptor to the core. The descriptor is found the way
     WireGuard's iOS app does it.

  It answers the app's status requests with the core's JSON.
- `PacketTunnel/PacketTunnel-Bridging-Header.h`: the core's C interface
  (`supernet.h`) plus the kernel-control declarations that the iOS SDK leaves out.
- `supernet.entitlements`: Network Extension (packet-tunnel-provider) and the App Group.

## Building (on a Mac)

1. The Rust core for `aarch64-apple-ios` (`libsupernet_ffi.a`). Either way works:
   - on the Mac: `IPHONEOS_DEPLOYMENT_TARGET=16.0 cargo build --release --target aarch64-apple-ios -p supernet-ffi`;
   - from Windows: `scripts/build-ios-lib.ps1`. It cross-compiles with Zig and
     needs `SDKSettings.json`, `usr/include` and `usr/lib` of a Mac's
     iPhoneOS SDK in `local/toolchain/iPhoneOS.sdk`. It writes `dist/ios/libsupernet_ffi.a`.
2. Build the app:
   - `ios/build.sh device` → `build/ios/device/superNET.app` and `superNET.ipa`;
   - `ios/build.sh simulator` → the UI only. The Simulator cannot run packet
     tunnels. To see it:
     - `xcrun simctl launch booted app.supernet.client -SupernetDemo` shows sample status;
     - `-SupernetSettings` opens the settings.

Installing on an iPhone needs a **paid** Apple Developer account, because free
accounts cannot use the Network Extension entitlement.

1. Create two App IDs, `app.supernet.client` and `app.supernet.client.tunnel`.
   Give both the App Group `group.app.supernet.client` and Network Extensions.
2. Make a development provisioning profile for each.
3. Run:

```bash
SIGN_IDENTITY="Apple Development: Name (TEAMID)" APP_PROFILE=app.mobileprovision TUNNEL_PROFILE=tunnel.mobileprovision ios/build.sh device
```

Without these settings, the bundle is signed ad hoc. That checks the build,
but the result cannot be installed.

## Verified (2026-11-09, MacBook Air M4, Xcode 27.1, iOS 27.1 SDK)

- `libsupernet_ffi.a` cross-built from Windows against the real iPhoneOS SDK headers.
- The extension compiled and linked with Apple's toolchain: no undefined symbols, no warnings.
- The app compiled.
- `codesign --verify --deep --strict` passes for the ad-hoc-signed bundle; the
  entitlements and `NSExtension` keys are as above.
- The UI ran in the iPhone 17 Simulator (iOS 27.1):
  - the main screen with sample status (topology, peer list);
  - the settings;
  - the not-yet-connected state.

## Not verified

- Running the tunnel on a real iPhone. That needs the paid account, so it has
  not been done.
- Untested on a device:
  - the extension's memory use, against the system limit for packet tunnels;
  - starting the tunnel from the app;
  - the status messages.
