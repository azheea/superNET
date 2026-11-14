import NetworkExtension
import os

/// The superNET VPN on iOS: a Network Extension packet tunnel that runs the
/// Rust core (libsupernet_ffi.a, see ios/supernet.h).
///
/// Same order as Android: join the virtual network first (its address is
/// part of the tunnel settings), then apply the settings, then hand the
/// tunnel's file descriptor to the core. The extension's own sockets are not
/// routed through its tunnel, so nothing loops back.
///
/// The profile is shared with the app through the App Group container
/// (`group.app.supernet.client/profile.yaml`).
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var handle: OpaquePointer?
    private let log = Logger(subsystem: "app.supernet.client.tunnel", category: "tunnel")
    private static let appGroup = "group.app.supernet.client"

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        guard let dir = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: Self.appGroup) else {
            completionHandler(Self.error("App Group 不可用"))
            return
        }
        let profile = dir.appendingPathComponent("profile.yaml").path
        // Engine start and mesh join can take seconds: off the extension's main queue.
        DispatchQueue.global(qos: .userInitiated).async {
            guard let h = supernet_prepare(profile, dir.path) else {
                completionHandler(Self.error("superNET 启动失败（配置无法读取？）"))
                return
            }
            // SupernetHandle is opaque in C, so Swift sees OpaquePointer.
            self.handle = h
            let mesh = Self.take(supernet_mesh_address(h)) ?? ""
            self.setTunnelNetworkSettings(Self.settings(mesh: mesh)) { error in
                if let error {
                    completionHandler(error)
                    return
                }
                guard let fd = self.tunnelFileDescriptor else {
                    completionHandler(Self.error("拿不到隧道的文件描述符"))
                    return
                }
                if supernet_attach_tun(h, fd) != 0 {
                    let message = Self.take(supernet_last_error(h)) ?? "接管隧道失败"
                    completionHandler(Self.error(message))
                    return
                }
                self.log.info("superNET started, mesh \(mesh, privacy: .public)")
                completionHandler(nil)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        if let h = handle {
            supernet_stop(h)
            handle = nil
        }
        completionHandler()
    }

    /// The app asks for status (JSON) with a provider message.
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let h = handle else {
            completionHandler?(nil)
            return
        }
        completionHandler?(Self.take(supernet_status_json(h))?.data(using: .utf8))
    }

    /// Same addresses, routes and DNS as the other platforms (see docs/DESIGN.md).
    private static func settings(mesh: String) -> NEPacketTunnelNetworkSettings {
        let s = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        var addresses = ["172.19.0.1"], masks = ["255.255.255.252"]
        if let slash = mesh.firstIndex(of: "/"), let prefix = Int(mesh[mesh.index(after: slash)...]) {
            addresses.append(String(mesh[..<slash]))
            masks.append(mask(prefix))
        }
        let v4 = NEIPv4Settings(addresses: addresses, subnetMasks: masks)
        v4.includedRoutes = [NEIPv4Route.default()]
        s.ipv4Settings = v4
        let v6 = NEIPv6Settings(addresses: ["fdfe:dcba:9876::1"], networkPrefixLengths: [126])
        v6.includedRoutes = [NEIPv6Route.default()]
        s.ipv6Settings = v6
        let dns = NEDNSSettings(servers: ["172.19.0.2", "fdfe:dcba:9876::2"])
        dns.matchDomains = [""]  // every domain
        s.dnsSettings = dns
        s.mtu = 1500
        return s
    }

    private static func mask(_ prefix: Int) -> String {
        let m: UInt32 = prefix == 0 ? 0 : ~UInt32(0) << (32 - UInt32(prefix))
        return [24, 16, 8, 0].map { String((m >> UInt32($0)) & 0xff) }.joined(separator: ".")
    }

    /// The utun descriptor behind packetFlow. NEPacketTunnelFlow has no public
    /// accessor; this is the approach WireGuard's iOS app uses: find the open
    /// utun control socket among the process's descriptors.
    private var tunnelFileDescriptor: Int32? {
        var ctlInfo = ctl_info()
        withUnsafeMutablePointer(to: &ctlInfo.ctl_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
                _ = strcpy($0, "com.apple.net.utun_control")
            }
        }
        for fd: Int32 in 0...1024 {
            var addr = sockaddr_ctl()
            var len = socklen_t(MemoryLayout.size(ofValue: addr))
            let ok = withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getpeername(fd, $0, &len) }
            }
            if ok != 0 || addr.sc_family != AF_SYSTEM { continue }
            if ctlInfo.ctl_id == 0 {
                if ioctl(fd, CTLIOCGINFO, &ctlInfo) != 0 { continue }
            }
            if addr.sc_id == ctlInfo.ctl_id { return fd }
        }
        return nil
    }

    private static func take(_ p: UnsafeMutablePointer<CChar>?) -> String? {
        guard let p else { return nil }
        defer { supernet_free_string(p) }
        return String(cString: p)
    }

    private static func error(_ message: String) -> NSError {
        NSError(domain: "superNET", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
