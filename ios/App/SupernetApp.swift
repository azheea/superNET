import CryptoKit
import NetworkExtension
import SwiftUI

/// The superNET app on iOS: a small native shell around the Packet Tunnel
/// extension (ios/PacketTunnel), which runs the Rust core.
///
/// - The profile (nodes, rules) is pasted in as YAML, the same format as on
///   the other platforms.
/// - Joining the virtual network takes the invite link and a device name;
///   the app makes the device key (X25519, like WireGuard) and adds the
///   `mesh:` section itself.
/// - Both go to `profile.yaml` in the App Group container, where the
///   extension reads them; status comes back from the extension as JSON.
@main
struct SupernetApp: App {
    @StateObject private var tunnel = TunnelController()

    var body: some Scene {
        WindowGroup {
            ContentView().environmentObject(tunnel)
        }
    }
}

// MARK: - Shared files

enum Shared {
    static let appGroup = "group.app.supernet.client"
    static let tunnelBundle = "app.supernet.client.tunnel"

    static var dir: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
    }

    static func url(_ name: String) -> URL? { dir?.appendingPathComponent(name) }

    static func read(_ name: String) -> String {
        guard let u = url(name), let s = try? String(contentsOf: u, encoding: .utf8) else { return "" }
        return s
    }

    /// Readable by the extension after the first unlock (the VPN may start while locked).
    static func write(_ name: String, _ text: String) throws {
        guard let u = url(name) else { throw AppError("App Group 不可用") }
        try Data(text.utf8).write(to: u, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }
}

struct AppError: LocalizedError {
    let message: String
    init(_ m: String) { message = m }
    var errorDescription: String? { message }
}

// MARK: - Mesh settings and the profile the extension reads

struct MeshSettings: Codable, Equatable {
    var invite = ""
    var name = UIDevice.current.name
    var privateKey = ""
    var relay = true

    var enabled: Bool { invite.hasPrefix("supernet-net://") && !privateKey.isEmpty }

    static func load() -> MeshSettings {
        (try? JSONDecoder().decode(MeshSettings.self, from: Data(Shared.read("mesh.json").utf8))) ?? MeshSettings()
    }

    func save() throws {
        try Shared.write("mesh.json", String(decoding: try JSONEncoder().encode(self), as: UTF8.self))
    }

    /// A new device key: X25519 (Curve25519) private key, base64 like WireGuard's.
    static func newKey() -> String {
        Curve25519.KeyAgreement.PrivateKey().rawRepresentation.base64EncodedString()
    }
}

enum ProfileText {
    /// The user's profile without a top-level `mesh:` section, plus ours.
    static func compose(user: String, mesh: MeshSettings) -> String {
        var out: [Substring] = []
        var skipping = false
        for line in user.split(separator: "\n", omittingEmptySubsequences: false) {
            let topLevel = !(line.first?.isWhitespace ?? true) && !line.hasPrefix("#")
            if topLevel { skipping = line.hasPrefix("mesh:") }
            if !skipping { out.append(line) }
        }
        var text = out.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty {
            // Nothing pasted: proxy nothing, only the virtual network.
            text = "mode: rule\nrules:\n- MATCH,DIRECT"
        }
        if mesh.enabled {
            text += """

            mesh:
              invite: \(quoted(mesh.invite))
              private_key: \(quoted(mesh.privateKey))
              name: \(quoted(mesh.name))
              relay: \(mesh.relay)
              enabled: true
            """
        }
        return text + "\n"
    }

    /// A YAML double-quoted scalar (JSON string escaping is valid YAML).
    static func quoted(_ s: String) -> String {
        let data = (try? JSONEncoder().encode(s)) ?? Data("\"\"".utf8)
        return String(decoding: data, as: UTF8.self)
    }
}

// MARK: - Status from the extension (crates/supernet-ffi, supernet_status_json)

struct TunnelStatus: Decodable {
    struct Engine: Decodable {
        var running: Bool?
        var connections: Int?
        var total_upload: UInt64?
        var total_download: UInt64?
    }
    struct Member: Decodable, Identifiable {
        var ip: String
        var name: String
        var online: Bool?
        var relay: Bool?
        var server: Bool?
        var id: String { ip }
    }
    struct Peer: Decodable, Identifiable {
        var ip: String
        var name: String
        var online: Bool?
        var server: Bool?
        var kind: PathKind
        var rtt_ms: UInt32?
        var via: String?
        var endpoint: String?
        var tx_bytes: UInt64?
        var rx_bytes: UInt64?
        var id: String { ip }
    }
    struct Link: Decodable {
        var from: String
        var peer: String
        var kind: PathKind
        var rtt_ms: UInt32?
        var via: String?
    }
    struct Mesh: Decodable {
        var network: String?
        var me: Member?
        var prefix: Int?
        var peers: [Peer]?
        var links: [Link]?
        var members: [Member]?
        var last_error: String?
    }
    var status: Engine?
    var mesh: Mesh?
    var tun_active: Bool?
}

enum PathKind: String, Decodable {
    case lan, ipv6, direct, peer, server, down

    var label: String {
        switch self {
        case .lan: return "局域网直连"
        case .ipv6: return "IPv6 直连"
        case .direct: return "公网直连"
        case .peer: return "设备中继"
        case .server: return "服务器中继"
        case .down: return "不通"
        }
    }

    var color: Color {
        switch self {
        case .lan: return .green
        case .ipv6: return .teal
        case .direct: return .blue
        case .peer: return .orange
        case .server: return .purple
        case .down: return .gray
        }
    }

    var dash: [CGFloat] {
        switch self {
        case .peer, .server: return [7, 5]
        case .down: return [2, 6]
        default: return []
        }
    }
}

// MARK: - The VPN configuration and its connection

@MainActor
final class TunnelController: ObservableObject {
    @Published var vpnStatus: NEVPNStatus = .invalid
    @Published var status: TunnelStatus?
    @Published var error: String?
    @Published var userProfile: String = Shared.read("user-profile.yaml")
    @Published var mesh = MeshSettings.load()

    private var manager: NETunnelProviderManager?
    private var timer: Timer?
    private var observer: NSObjectProtocol?

    init() {
        if CommandLine.arguments.contains("-SupernetDemo") {
            loadDemo()
            return
        }
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.refreshStatus() }
        }
        Task { await load() }
    }

    var connected: Bool { vpnStatus == .connected }
    var busy: Bool { vpnStatus == .connecting || vpnStatus == .disconnecting || vpnStatus == .reasserting }

    func load() async {
        do {
            let all = try await NETunnelProviderManager.loadAllFromPreferences()
            manager = all.first
            refreshStatus()
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// Profile text the extension will read.
    func saveProfile() throws {
        if mesh.invite.hasPrefix("supernet-net://") && mesh.privateKey.isEmpty {
            mesh.privateKey = MeshSettings.newKey()
        }
        try mesh.save()
        try Shared.write("user-profile.yaml", userProfile)
        try Shared.write("profile.yaml", ProfileText.compose(user: userProfile, mesh: mesh))
    }

    func connect() async {
        error = nil
        do {
            try saveProfile()
            let m = manager ?? NETunnelProviderManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = Shared.tunnelBundle
            proto.serverAddress = "superNET"
            m.protocolConfiguration = proto
            m.localizedDescription = "superNET"
            m.isEnabled = true
            // The system asks the user to allow the VPN the first time.
            try await m.saveToPreferences()
            try await m.loadFromPreferences()
            manager = m
            try m.connection.startVPNTunnel()
        } catch {
            self.error = error.localizedDescription
        }
    }

    func disconnect() {
        manager?.connection.stopVPNTunnel()
    }

    /// A new device key: this device joins the network as a new member.
    func resetMeshKey() {
        mesh.privateKey = MeshSettings.newKey()
        try? mesh.save()
    }

    private func refreshStatus() {
        vpnStatus = manager?.connection.status ?? .invalid
        timer?.invalidate()
        guard vpnStatus == .connected else {
            if vpnStatus == .disconnected { status = nil }
            return
        }
        poll()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.poll() }
        }
    }

    private func poll() {
        guard let session = manager?.connection as? NETunnelProviderSession else { return }
        try? session.sendProviderMessage(Data("status".utf8)) { [weak self] data in
            guard let data, let s = try? JSONDecoder().decode(TunnelStatus.self, from: data) else { return }
            Task { @MainActor in self?.status = s }
        }
    }

    /// UI check without a tunnel (`-SupernetDemo`, e.g. in the Simulator).
    private func loadDemo() {
        vpnStatus = .connected
        let json = """
        {"status":{"running":true,"connections":7,"total_upload":1048576,"total_download":8388608},"tun_active":true,
         "mesh":{"network":"superNET","prefix":24,
          "me":{"ip":"10.66.0.7","name":"iPhone","online":true,"relay":true,"server":false},
          "members":[{"ip":"10.66.0.1","name":"服务器","online":true,"server":true},{"ip":"10.66.0.3","name":"AZHE","online":true},
                     {"ip":"10.66.0.4","name":"MuMu","online":true},{"ip":"10.66.0.6","name":"MacBook","online":true},{"ip":"10.66.0.7","name":"iPhone","online":true}],
          "peers":[{"ip":"10.66.0.1","name":"服务器","online":true,"server":true,"kind":"direct","rtt_ms":205},
                   {"ip":"10.66.0.3","name":"AZHE","online":true,"kind":"lan","rtt_ms":4,"endpoint":"192.168.31.9:64984"},
                   {"ip":"10.66.0.4","name":"MuMu","online":true,"kind":"peer","rtt_ms":9,"via":"10.66.0.3"},
                   {"ip":"10.66.0.6","name":"MacBook","online":true,"kind":"ipv6","rtt_ms":6}],
          "links":[{"from":"10.66.0.3","peer":"10.66.0.4","kind":"lan","rtt_ms":3},{"from":"10.66.0.3","peer":"10.66.0.6","kind":"lan","rtt_ms":16}]}}
        """
        status = try? JSONDecoder().decode(TunnelStatus.self, from: Data(json.utf8))
        mesh.invite = "supernet-net://203.0.113.10:19190?…"
    }
}

// MARK: - Screens

struct ContentView: View {
    @EnvironmentObject var tunnel: TunnelController
    /// `-SupernetSettings` opens the settings at launch (UI checks in the Simulator).
    @State private var editing = CommandLine.arguments.contains("-SupernetSettings")

    var body: some View {
        NavigationStack {
            List {
                Section {
                    HStack {
                        Circle().fill(tunnel.connected ? Color.green : Color.secondary).frame(width: 10, height: 10)
                        Text(statusText).font(.headline)
                        Spacer()
                        if tunnel.busy { ProgressView() }
                    }
                    Button(tunnel.connected ? "断开" : "连接") {
                        if tunnel.connected { tunnel.disconnect() } else { Task { await tunnel.connect() } }
                    }
                    .disabled(tunnel.busy)
                    if let e = tunnel.error ?? tunnel.status?.mesh?.last_error {
                        Text(e).font(.footnote).foregroundStyle(.red)
                    }
                    if let s = tunnel.status?.status {
                        LabeledContent("连接数", value: "\(s.connections ?? 0)")
                        LabeledContent("上传 / 下载", value: "\(bytes(s.total_upload)) / \(bytes(s.total_download))")
                    }
                }

                if let mesh = tunnel.status?.mesh, let me = mesh.me {
                    Section("组网 · \(mesh.network ?? "")") {
                        LabeledContent("本机", value: "\(me.ip)/\(mesh.prefix ?? 24)")
                        TopologyView(mesh: mesh).frame(height: 300).listRowInsets(EdgeInsets())
                        ForEach(mesh.peers ?? []) { p in
                            HStack {
                                Text(p.server == true ? "服务器" : p.name)
                                Text(p.ip).font(.caption).foregroundStyle(.secondary)
                                Spacer()
                                Text(p.kind.label + (p.rtt_ms.map { " · \($0) ms" } ?? "")).font(.caption).foregroundStyle(p.kind.color)
                            }
                        }
                    }
                }

                Section("设置") {
                    Button("配置与组网") { editing = true }.disabled(tunnel.connected || tunnel.busy)
                    if tunnel.connected { Text("断开后才能修改配置").font(.footnote).foregroundStyle(.secondary) }
                }
            }
            .navigationTitle("superNET")
            .sheet(isPresented: $editing) { SettingsView() }
        }
    }

    var statusText: String {
        switch tunnel.vpnStatus {
        case .connected: return "已连接"
        case .connecting: return "正在连接…"
        case .disconnecting: return "正在断开…"
        case .reasserting: return "正在重连…"
        case .disconnected: return "未连接"
        default: return "未配置"
        }
    }

    func bytes(_ v: UInt64?) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(v ?? 0), countStyle: .binary)
    }
}

struct SettingsView: View {
    @EnvironmentObject var tunnel: TunnelController
    @Environment(\.dismiss) private var dismiss
    @State private var saveError: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("supernet-net://…", text: $tunnel.mesh.invite, axis: .vertical)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    TextField("设备名", text: $tunnel.mesh.name)
                    Toggle("为其他设备中继", isOn: $tunnel.mesh.relay)
                    Button("从剪贴板粘贴邀请链接") {
                        if let s = UIPasteboard.general.string?.trimmingCharacters(in: .whitespacesAndNewlines) { tunnel.mesh.invite = s }
                    }
                    if !tunnel.mesh.privateKey.isEmpty {
                        Button("换一个设备密钥（作为新设备加入）", role: .destructive) { tunnel.resetMeshKey() }
                    }
                } header: {
                    Text("组网")
                } footer: {
                    Text("邀请链接在电脑版的“组网”页里，或用 supernet-coord invite 查看。留空则不加入组网。")
                }
                Section {
                    TextEditor(text: $tunnel.userProfile)
                        .font(.system(.footnote, design: .monospaced))
                        .frame(minHeight: 220)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    Button("从剪贴板粘贴配置") {
                        if let s = UIPasteboard.general.string { tunnel.userProfile = s }
                    }
                } header: {
                    Text("代理配置（YAML）")
                } footer: {
                    Text("与电脑版相同的配置格式（节点、分组、规则）。其中的 mesh 段会被上面的组网设置替换。")
                }
                if let e = saveError { Text(e).foregroundStyle(.red) }
            }
            .navigationTitle("配置")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") {
                        do {
                            try tunnel.saveProfile()
                            dismiss()
                        } catch {
                            saveError = error.localizedDescription
                        }
                    }
                }
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
            }
        }
    }
}

/// Same layout as the desktop topology (app/src/pages/Topology.tsx): this
/// device in the middle, the server on top, the others around; relayed links
/// bend through the relay.
struct TopologyView: View {
    let mesh: TunnelStatus.Mesh

    var body: some View {
        GeometryReader { geo in
            let layout = Layout(mesh: mesh, size: geo.size)
            ZStack {
                Canvas { ctx, _ in
                    for e in layout.edges {
                        guard let a = layout.pos[e.a], let b = layout.pos[e.b] else { continue }
                        // A relayed link is a curve through the relay (at t = 0.5).
                        var control: CGPoint?
                        if let v = e.via, let c = layout.pos[v] {
                            control = CGPoint(x: 2 * c.x - (a.x + b.x) / 2, y: 2 * c.y - (a.y + b.y) / 2)
                        }
                        var path = Path()
                        path.move(to: a)
                        if let control { path.addQuadCurve(to: b, control: control) } else { path.addLine(to: b) }
                        ctx.stroke(path, with: .color(e.kind.color.opacity(e.mine ? 0.95 : 0.5)),
                                   style: StrokeStyle(lineWidth: e.mine ? 2.5 : 1.5, lineCap: .round, dash: e.kind.dash))
                        if e.mine, e.kind != .down, let rtt = e.rtt {
                            // Nearer this device than the far end (whose name sits below
                            // it), and beside the line rather than on it.
                            let t: CGFloat = control == nil ? 0.42 : 0.28
                            let at = Self.point(a, control ?? CGPoint(x: (a.x + b.x) / 2, y: (a.y + b.y) / 2), b, t)
                            let ahead = Self.point(a, control ?? CGPoint(x: (a.x + b.x) / 2, y: (a.y + b.y) / 2), b, t + 0.02)
                            let dx = ahead.x - at.x, dy = ahead.y - at.y, len = max(hypot(dx, dy), 0.001)
                            var n = CGPoint(x: -dy / len, y: dx / len)
                            if n.x < 0 || (n.x == 0 && n.y > 0) { n = CGPoint(x: -n.x, y: -n.y) }
                            // The text is wide and short: move further when pushed sideways.
                            let away = 10 + abs(n.x) * 24
                            ctx.draw(Text("\(rtt) ms").font(.caption2).foregroundColor(e.kind.color),
                                     at: CGPoint(x: at.x + n.x * away, y: at.y + n.y * away))
                        }
                    }
                }
                ForEach(layout.nodes, id: \.ip) { n in
                    VStack(spacing: 2) {
                        ZStack {
                            Circle().fill(n.isMe ? Color.accentColor : Color(.secondarySystemBackground))
                            Circle().stroke(n.online ? Color.accentColor : Color.secondary, lineWidth: 1.5)
                            Text(n.badge).font(.caption.bold()).foregroundStyle(n.isMe ? Color.white : Color.primary)
                        }
                        .frame(width: n.isMe ? 44 : 36, height: n.isMe ? 44 : 36)
                        VStack(spacing: 0) {
                            Text(n.name).font(.caption2).lineLimit(1)
                            Text(n.ip).font(.system(size: 9)).foregroundStyle(.secondary)
                        }
                        .padding(.horizontal, 3)
                        .background(Color(.secondarySystemGroupedBackground).opacity(0.85), in: RoundedRectangle(cornerRadius: 4))
                    }
                    .frame(width: 90)
                    .position(x: layout.pos[n.ip]?.x ?? 0, y: (layout.pos[n.ip]?.y ?? 0) + 14)
                }
            }
        }
        .padding(.vertical, 8)
    }

    /// Point at t on the quadratic curve a → b with control c.
    static func point(_ a: CGPoint, _ c: CGPoint, _ b: CGPoint, _ t: CGFloat) -> CGPoint {
        let u = 1 - t
        return CGPoint(x: u * u * a.x + 2 * u * t * c.x + t * t * b.x, y: u * u * a.y + 2 * u * t * c.y + t * t * b.y)
    }

    struct Node {
        let ip: String, name: String, badge: String, online: Bool, isMe: Bool
    }

    struct Edge {
        let a: String, b: String, kind: PathKind, rtt: UInt32?, via: String?, mine: Bool
    }

    struct Layout {
        var pos: [String: CGPoint] = [:]
        var nodes: [Node] = []
        var edges: [Edge] = []

        init(mesh: TunnelStatus.Mesh, size: CGSize) {
            guard let me = mesh.me else { return }
            let members = mesh.members ?? []
            let server = members.first { $0.server == true }
            let others = members.filter { $0.ip != me.ip && $0.server != true }
            let c = CGPoint(x: size.width / 2, y: size.height / 2 - 10)
            let r = min(size.width, size.height) / 2 - 42
            pos[me.ip] = c
            nodes.append(Node(ip: me.ip, name: me.name, badge: "本机", online: true, isMe: true))
            if let s = server {
                pos[s.ip] = CGPoint(x: c.x, y: c.y - r)
                nodes.append(Node(ip: s.ip, name: "服务器", badge: "服", online: s.online ?? true, isMe: false))
            }
            let slots = others.count + (server == nil ? 0 : 1)
            let skew = server != nil && others.count % 2 == 1 ? 25 * Double.pi / 180 : 0
            for (i, m) in others.enumerated() {
                let angle = -Double.pi / 2 + skew + (Double(i) + (server == nil ? 0.5 : 1)) * 2 * Double.pi / Double(max(slots, 1))
                pos[m.ip] = CGPoint(x: c.x + r * cos(angle), y: c.y + r * sin(angle))
                nodes.append(Node(ip: m.ip, name: m.name, badge: String(m.name.prefix(1)), online: m.online ?? false, isMe: false))
            }
            for p in mesh.peers ?? [] {
                let via = p.kind == .peer ? p.via : p.kind == .server ? server?.ip : nil
                edges.append(Edge(a: me.ip, b: p.ip, kind: p.kind, rtt: p.rtt_ms, via: via == p.ip ? nil : via, mine: true))
            }
            for l in mesh.links ?? [] where l.from != me.ip && l.peer != me.ip {
                let via = l.kind == .peer ? l.via : l.kind == .server ? server?.ip : nil
                edges.append(Edge(a: l.from, b: l.peer, kind: l.kind, rtt: l.rtt_ms, via: via, mine: false))
            }
        }
    }
}
