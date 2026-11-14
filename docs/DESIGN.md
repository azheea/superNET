# superNET 设计（草案 v0.1，2026-11-08）

## 1. 目标

- **规则分流代理**：命中规则的流量从节点（你自己的公网服务器）出去，其余流量照常走本机网络，不受影响。
- **五个平台**：Windows / macOS / Linux / Android / iOS，共用一套 Tauri 2 界面和一份 Rust 核心。
- **节点由用户自己添加**：粘贴或导入 WireGuard 配置、扫二维码、打开 `supernet://` 链接。
- **虚拟内网**：节点所在的私网网段（例如 `10.66.0.0/24`）可以从客户端直接访问。

第一版不做：机场订阅里的 SS/VMess/Trojan 等节点、多用户计费面板。

## 2. 总体结构

```
┌──────────────────── 客户端设备 ────────────────────┐
│  Tauri 界面（React + Fluent UI）                     │
│          │ 本机 IPC                                  │
│  supernet-core（Rust）                               │
│    入站   TUN / 本地 HTTP+SOCKS5                      │
│    DNS    Fake-IP + 分流解析                          │
│    规则   顺序匹配，选出站                             │
│    出站   DIRECT │ REJECT │ 节点（WireGuard）          │
└──────────┬──────────────────────────┬────────────────┘
           │ 直连                      │ WireGuard（UDP）
        本机网卡                  公网服务器（节点）
                                  wg0 + NAT → 互联网 / 节点内网
```

## 3. 流量怎么接管

| 模式 | 需要的权限 | 覆盖范围 | 平台 |
|---|---|---|---|
| 系统代理 | 无 | 遵守系统代理设置的应用（浏览器等） | Win / mac / Linux |
| TUN · 精确路由（默认） | 管理员 / VPN 授权 | 全部应用 | 全平台 |
| TUN · 全局接管 | 同上 | 全部应用；支持按进程分流、"非国内走节点"这类兜底规则 | 全平台 |

### 精确路由（默认）

你的需求是“命中才走节点，其余直连”，也就是最后一条规则为 `MATCH,DIRECT`。这时 TUN 只接管两类目的地址：

1. **Fake-IP 段 `198.18.0.0/15`**：系统发 DNS 查询时，superNET 就按域名规则判定。判给节点的域名返回 Fake-IP，判给直连的返回真实 IP。
2. **规则里指向节点的 IP 段**：例如节点内网 `IP-CIDR,10.66.0.0/24,代理`。

其余流量在系统路由这一层就不进 TUN，直接走原网卡。游戏、局域网、国内应用完全不经过 superNET，也就不会出现回环。

DNS 由 superNET 接管：TUN 网卡上的 `198.18.0.2` 作为系统 DNS。DNS 阶段的判定方法：按顺序检查规则，域名类规则直接比较；遇到 IP 类规则（`IP-CIDR` / `GEOIP`，且没有标 `no-resolve`）时，先用直连 DNS 解析，再比较。第一条命中的规则决定结果。

以下情况会**自动改用全局接管**，因为这些规则必须看到每条连接才能判定：

- 有 `PROCESS-NAME` / `PACKAGE` 规则指向节点；
- 最后一条是 `MATCH,节点`；
- `GEOIP` 等规则把大段地址判给节点。

### 防回环

- 直连出站的 socket 绑定物理网卡：Windows 用 `IP_UNICAST_IF`，macOS 用 `IP_BOUND_IF`，Linux 用 `SO_BINDTODEVICE` 或 fwmark；Android 通过 VpnService 把本应用排除在外。
- 节点的 endpoint IP 永远不加入 TUN 路由。

## 4. 数据通路（TUN 模式）

1. 从 TUN 读出 IP 包，交给**入站用户态协议栈**（smoltcp），还原成 TCP 流和 UDP 会话。
2. 目的地址如果是 Fake-IP，查表得到域名；否则直接用 IP。可选嗅探 TLS SNI 或 HTTP Host。
3. 规则引擎选出站。
4. 按出站类型处理：
   - **DIRECT**：普通系统 socket（绑物理网卡），域名用本地 DNS 解析。
   - **节点**：每个 WireGuard 节点有一个**隧道内协议栈**（smoltcp），加解密由 boringtun 负责，在隧道里发起 TCP/UDP。域名通过节点的 DNS（经隧道）解析，本地不会泄漏。
   - **REJECT**：TCP 回 RST，UDP 回 ICMP 不可达。
5. 双向转发，统计流量，记入连接列表。

**为什么在 L4（TCP/UDP）这一层转发，而不是把原始 IP 包直接塞进 WireGuard：**

- Fake-IP 要按连接改写成真实目标，L4 上做最直接；
- 所有出站共用 `dial_tcp` / `dial_udp` 接口，以后加 SOCKS5、HTTP 或其他传输协议，只需要再实现一个 Outbound。

代价是多一层用户态协议栈。个人使用的吞吐应该够，具体数字需要实测。

## 5. 规则

语法兼容 Clash，现成的规则列表可以直接粘贴使用。

| 类型 | 说明 |
|---|---|
| `DOMAIN` / `DOMAIN-SUFFIX` / `DOMAIN-KEYWORD` | 域名精确匹配 / 后缀匹配 / 包含关键字 |
| `IP-CIDR` / `IP-CIDR6` | 支持 `no-resolve` |
| `GEOIP` | 读取 mmdb 文件 |
| `DST-PORT` | 目的端口 |
| `PROCESS-NAME` | 仅桌面端 |
| `PACKAGE` | 仅 Android |
| `RULE-SET` | 本地或远程规则列表，定时更新 |
| `MATCH` | 兜底规则 |

- **策略**：`DIRECT`、`REJECT`、节点名、策略组名。
- **策略组**：`select`（手动选择）、`url-test`（自动选延迟最低的）、`fallback`（故障转移）。
- **模式**：规则 / 全局 / 直连，一键切换。
- **规则测试**：输入域名或 IP，显示命中哪一条规则、走哪个出口。
- **匹配实现**：保持“第一条命中即生效”的语义。连续的同类规则合并成带索引的块：域名后缀用哈希表或 trie，关键字用 Aho-Corasick，CIDR 用前缀树。

## 6. 配置示例（YAML，Clash 风格）

```yaml
mode: rule                 # rule | global | direct
tun:
  enable: true
  route: auto              # auto = 能用精确路由就用，否则全局接管
dns:
  direct: [system, https://223.5.5.5/dns-query]
  fake_ip_range: 198.18.0.0/15
nodes:
  - name: 东京
    type: wireguard
    endpoint: 203.0.113.10:51820
    private_key: "<客户端私钥>"
    public_key: "<服务端公钥>"
    address: [10.66.0.2/32, fd66::2/128]
    allowed_ips: [0.0.0.0/0, ::/0]
    dns: 10.66.0.1
    mtu: 1280
groups:
  - name: 代理
    type: select
    nodes: [东京]
rules:
  - IP-CIDR,10.66.0.0/24,代理,no-resolve   # 节点内网
  - DOMAIN-SUFFIX,github.com,代理
  - RULE-SET,my-list,代理
  - MATCH,DIRECT
rule_sets:
  my-list: { url: "https://example.com/list.txt", interval: 86400 }
```

## 7. 节点（服务端）

- 用标准 Linux WireGuard（内核 `wg`）+ nftables masquerade，并打开 `ip_forward`。
- 仓库 `node/` 目录提供：
  - `install.sh`：安装 wireguard-tools，生成服务端密钥，写 `wg0.conf`，开启转发和 NAT，用 systemd 设置开机启动；
  - `supernet-node peer add <名字>`：分配内网地址，输出客户端配置、二维码和 `supernet://` 链接；另有 `peer list` / `peer remove`。
- 客户端只认标准 WireGuard 配置，所以任何现成的 WireGuard 服务器（包括云厂商的一键镜像）都能直接添加。

### 在 1 核 1G 的服务器上稳定运行

节点服务器是 1 核 CPU、1G 内存，下面每一项都按这个规格来定：

- **首选内核 WireGuard**：加解密在内核里完成，只占几 MB 内存，没有常驻用户态进程，也就不会有进程崩溃或内存泄漏的问题。Linux 5.6 起内核自带；更老的内核由安装脚本装 DKMS 模块。
- **不跑常驻管理进程**：`supernet-node` 只是命令行工具，执行完就退出，平时占用为零。
- **装不上内核模块时自动降级**：OpenVZ、LXC 这类容器 VPS 常常不能加载内核模块。安装脚本会先检测虚拟化类型和 `/dev/net/tun`：
  - 有 TUN：改用用户态 WireGuard（boringtun，常驻内存约 10MB）；
  - 连 TUN 都没有：报告原因并停止安装，不留半装的状态。不需要 TUN 的纯用户态出口节点放到后续里程碑。
- **针对 1G 内存的调优**（只改转发必需的项，改动前先备份）：
  - `nf_conntrack_max` 设为 65536（约占 20MB），避免连接很多时连接跟踪表把内存吃满；
  - 开 BBR + fq；
  - nftables 做 MSS 钳制，防止 MTU 问题导致部分网站打不开；
  - 客户端默认 `PersistentKeepalive = 25`，保持 NAT 映射不过期。
- **开机自启**：用 systemd 的 `wg-quick@wg0`，重启后自动恢复。
- **安装脚本可重复执行**：已装好的步骤会跳过；`uninstall` 能恢复安装前的转发和防火墙设置。
- **上线前在这台机器上验收**（M3）：
  - 经隧道持续跑 30 分钟流量，记录 CPU、内存（`free -m`）和握手状态（`wg show`）；
  - 重启服务器后确认自动恢复。
  - 两项结果都写进进度记录。
- 可选：服务器有多个 IP 或一段 IPv6 时，按 peer 做 SNAT，每台设备一个独立出口 IP。
- 虚拟内网：把服务器所在私网和其他 peer 的地址写进 `AllowedIPs` 和 `IP-CIDR` 规则，客户端就能直接访问。

## 8. 各平台实现

### Windows

- **TUN**：wintun。随安装包附带 `wintun.dll`，驱动签名由 WireGuard 项目提供。
- **权限**：安装一个 Windows 服务 `superNET Service`，以 SYSTEM 身份运行核心；界面以普通用户运行，通过命名管道控制。只有首次安装服务时弹一次 UAC。系统代理模式不需要这个服务。
- **路由 / DNS**：用 IP Helper API 加路由；TUN 网卡设 DNS 并设为最低跃点。注意 Windows 会在多块网卡上并行发 DNS 查询（smart multi-homed resolution），需要处理，否则会漏判。
- **进程规则**：用 `GetExtendedTcpTable` / `GetExtendedUdpTable` 查 PID。

### macOS（有 Mac，没有付费账号）

- 没有付费账号就不能用 Network Extension，改用以下方式：
  - **系统代理模式**：用 `networksetup` 设置，不需要特权；
  - **TUN**：首次开启时输入管理员密码，安装一个 LaunchDaemon 辅助进程（以 root 运行核心并打开 utun），界面通过 Unix socket 控制它。
- **签名**：ad-hoc 自签。本机使用时需要“右键 → 打开”一次；分发给别人会被 Gatekeeper 拦截。
- **有付费账号以后**：换成 NEPacketTunnelProvider（System Extension），核心代码不用改。

### Linux

- **TUN**：`/dev/net/tun`。核心作为 systemd 服务运行（root 或 `CAP_NET_ADMIN`），或者给二进制加 `setcap` 后由界面直接拉起。
- **路由 / DNS**：用 rtnetlink 加路由；DNS 通过 systemd-resolved 的单网卡 DNS（`resolvectl`）接管。没有 resolved 时改写 `resolv.conf`，退出时恢复备份。
- **打包**：AppImage / deb（Tauri 自带）。

### Android

- **VpnService**：做成 Tauri 2 移动插件（Kotlin）。负责建立 TUN、只 `addRoute` 精确路由段、用 `addDisallowedApplication(本应用)` 防回环，然后把 fd 交给 Rust 核心。
- **常驻**：前台服务 + 常驻通知，关掉界面 VPN 也不断；提供快捷设置磁贴开关。
- **按应用分流**：利用 VpnService 的允许 / 排除应用列表，可以设置“只让某些 App 走规则”。
- **`PACKAGE` 规则**：用 `ConnectivityManager.getConnectionOwnerUid` 实现，需要 Android 10 及以上；其余功能跟随 Tauri 2 的最低版本（API 24）。

### iOS（目前受账号限制）

- iOS 上只能用 Network Extension（NEPacketTunnelProvider），必须有付费开发者账号（每年 99 美元）。免费账号拿不到这个权限，所以**目前无法在 iPhone 上开启 VPN**。
- **先做好的准备**：
  - Rust 核心编译成 xcframework，扩展用 Swift 写一层薄壳；
  - 在 Tauri 生成的 Xcode 工程里加扩展 target 和 App Group。
  - 代码先写好，等有账号再签名装到真机。
- **过渡办法**：电脑上的 superNET 打开“允许局域网连接”，iPhone 在 Wi-Fi 设置里把 HTTP 代理指向这台电脑。只覆盖遵守系统代理设置的 App。
- **内存**：NE 进程有内存上限（约 50MB），核心要控制缓冲区大小。

## 9. 代码结构

```
superNET/
  crates/
    supernet-core/      规则、DNS、Fake-IP、出站接口、连接管理、统计（纯 Rust，无平台代码）
    supernet-netstack/  TUN 入站协议栈（IP 包 ↔ TCP/UDP）
    supernet-wg/        WireGuard 出站：boringtun + smoltcp 隧道内协议栈
    supernet-platform/  TUN 设备、路由、DNS 接管、系统代理、绑物理网卡、进程查找
    supernetd/          桌面后台进程（Windows 服务 / LaunchDaemon / systemd）
    supernet-ffi/       给 iOS 用的 C ABI
  app/                  Tauri 2 + React + Fluent UI（和“星之救援者”启动器同一套技术栈）
    src/                界面
    src-tauri/          Tauri 端；plugins/vpn-android（Kotlin VpnService）
  node/                 服务端安装脚本、peer 管理
  docs/
```

主要候选依赖：tokio、boringtun、smoltcp、tun-rs、hickory-dns、maxminddb、aho-corasick。真正写代码前逐个核对版本和许可证。

## 10. 界面

- **首页**：连接开关、当前模式、实时速度、出口 IP 检测。
- **节点**：添加（粘贴配置 / 扫码 / 手动填写）、测延迟、选择当前节点。
- **规则**：规则列表、规则集更新、规则测试。
- **连接**：实时连接列表（域名、命中的规则、出站、流量），可以断开单条连接。
- **日志**、**设置**（模式、开机启动、DNS、允许局域网、语言）。

## 11. 安全

- **私钥**：存放在应用数据目录，权限仅限当前用户。桌面端可选存进系统钥匙串（Windows 凭据管理器 / macOS 钥匙串 / Secret Service）。
- **控制通道只在本机**：命名管道或 Unix socket，带访问控制，不监听网络端口。
- **本地代理端口**：默认只监听 `127.0.0.1`；“允许局域网连接”需要手动打开。
- **故障恢复**：退出或崩溃后恢复系统代理、路由和 DNS。下次启动时先检查有没有残留设置。

## 12. 里程碑

| 阶段 | 内容 | 状态（2026-11-09） |
|---|---|---|
| M1 | 核心 + 系统代理模式：规则引擎、WireGuard 出站、HTTP/SOCKS5 入站、配置导入、基础界面 | **已完成** |
| M2 | Windows TUN：wintun、Fake-IP DNS、精确路由、WFP DNS 防泄漏 | **已完成**（以管理员身份运行，没有做后台服务） |
| M3 | 节点脚本 + 真实节点联调 | 你的 CentOS 8 服务器（已完成，见 PROGRESS） |
| M3.5 | 原生抗丢包传输：Hysteria2（已完成，实测 3.8–4.4 MB/s）；TUIC 待定 | 同一台服务器 |
| M2.5 | 虚拟组网：P2P 优先、组内设备中继、服务器兜底、实时拓扑图（第 15 节） | **已完成**：电脑、Android、Linux 实测互通；IPv6 直连只有自动测试 |
| M4 | Android：VpnService、前台服务、组网、正式版签名 | **已完成**（MuMu 实测）；没有按应用分流；真手机打洞没测 |
| M5 | Linux：TUN、组网、命令行，静态 musl 程序 | **已完成**（在服务器上用独立网络命名空间实测）；没打 AppImage/deb |
| M6 | macOS：系统代理 + utun TUN + 构建脚本 | 代码完成、交叉检查通过，**等在 Mac 上验证** |
| M7 | iOS：xcframework + NE 扩展工程 | 等付费账号 |
| M8 | 增强：规则集订阅、url-test、更多传输协议 | — |

### 实测结论：传输层要能扛丢包（2026-11-08）

从你的家庭网络到节点服务器（往返 225 ms）的实测：

| 路径 | 速度 |
|---|---|
| WireGuard 直连 UDP | 约 57 KB/s，下行约 25% 丢包（ping 不丢包，是运营商在限制出境 UDP） |
| WireGuard 经 Clash → TUIC（native 模式） | 约 5 KB/s |
| WireGuard 经 Clash → TUIC（quic 模式） | 约 0.3 KB/s |
| WireGuard 经 Clash → vless（TCP） | 约 35 KB/s（vless 本身也只有约 39 KB/s） |
| 对照：你的 Clash 默认线路（Auto，基于 QUIC） | 约 1.2 MB/s |

**结论**：在这种网络上，WireGuard 不适合做出口传输，它只适合做虚拟内网，以及在 UDP 正常的网络上使用。真正快的路径是基于 QUIC、能扛丢包的协议，所以 M3.5 在 superNET 里原生实现 Hysteria2 / TUIC（TLS 1.3 加密，直接连 s-ui）。

**本机入口保持不变**（用户决定）：HTTP + SOCKS5 只监听 127.0.0.1，数据不离开本机；“允许局域网连接”默认关闭，打开后同一网络里的设备不需要认证就能使用。

**出口只用加密传输**（用户要求）：不提供 SOCKS5 / HTTP 这类明文协议的上游节点，也不把 WireGuard 转交给 SOCKS5 代理。这两个功能曾短暂实现，已删除。

## 13. 验证方式

- **单元测试**：规则解析与匹配、Fake-IP 地址池、DNS 判定。
- **集成测试**（不联网、不需要管理员）：在进程内起一个假节点（boringtun + 用户态协议栈 + 本地 echo/HTTP 服务）。客户端从 SOCKS5 入站，经规则和 WireGuard 到达假节点，检查以下几点：
  - TCP 和 UDP 都能通；
  - 走节点的域名不在本地解析；
  - 直连流量不进隧道。
- **真实联调**：需要一台能随意改网络配置的 Linux 公网服务器（root）。
- **记录方式**：协议/单元测试结果和真实设备上的验收分开记录，没跑过的检查不写成通过。

本机环境（2026-11-08 检查）：

| 项目 | 状态 |
|---|---|
| Rust 1.99.1 | 已装；target 有 msvc、gnu、aarch64-linux-android |
| Node 22.16 / JDK 17 | 已装 |
| Android SDK（`~/Android/Sdk`） | 只有 NDK 27.2 和 build-tools 34；缺 platforms、platform-tools、cmdline-tools，M4 前需要补装 |
| WSL / Docker | 没有，M5 需要装 WSL 或用远程机器 |

## 14. 风险与待定

- **WireGuard 握手特征固定**，跨境链路上可能被识别、限速或阻断。出站已经抽象成接口，之后可以加别的传输协议；第一版只做 WireGuard。
- **Windows 端**：DNS 并行查询；部分安全软件会拦截 wintun 或修改路由的操作。
- **未签名分发**：Windows 会弹 SmartScreen 警告，macOS 会被 Gatekeeper 拦截。
- **iOS** 受账号限制，见第 8 节。
- **待你决定**：用哪台服务器做测试节点。不建议用正在跑游戏服的机器，因为要改它的转发和 NAT 配置。

## 15. 虚拟组网：P2P 优先，组内设备互为中继（草案，2026-11-09）

### 已定（用户，2026-11-09）

- 协调服务使用 UDP 19190，跑在 203.0.113.10 上，需要在安全组放行。
- **沿用 10.66.0.0/24**：服务器（10.66.0.1，内核 wg0）也是网内成员；协调服务负责把新设备登记进 wg0。网内最多约 250 台设备。
- **所有设备默认允许当中继**，包括手机；界面上标明“正在为别人中继”和中继流量。
- 中继只在两台设备直连不通时才用，平时各走各的直连，不为均摊负载而绕路。
- 软件里实时画出**拓扑图**（见下文“拓扑图”）。

### 目标

- 同一个网络里的设备各有一个固定的虚拟地址（`10.66.0.0/24`，和服务器现有的 wg0 是同一个网段），可以互相访问：远程桌面、共享文件夹、SSH、游戏联机等。
- 能直连就直连（P2P）；直连不了，就由组内另一台设备转发；都不行，最后由服务器转发。
- 端到端加密：中继设备和服务器只经手密文。

### 组成

```
           ┌──────────── 协调服务 supernet-coord（你的服务器）────────────┐
           │  成员名单、公钥、地址分配    地址探测（看到的公网地址）    兜底中继  │
           └──────▲─────────────────────────▲──────────────────────▲────┘
                  │ 控制通道（QUIC + TLS 1.3，  │ UDP                    │ UDP
                  │  证书指纹固定）             │                        │
   设备 A ────────┴──── 同一个 UDP 套接字 ──────┴────────────────────────┘
     │  ① 局域网直连  ② IPv6 直连  ③ IPv4 打洞直连  ④ 经设备 B 转发  ⑤ 经服务器转发
   设备 C
```

- **协调服务**是一个新的小程序，跑在你的服务器上（systemd 服务）。预计内存 20 MB 以内，不碰 s-ui 和现有的 wg0。它只做三件事：
  - 管理成员名单：设备公钥、虚拟地址、可达地址；
  - 告诉设备它在公网上看起来是什么地址（类似 STUN）；
  - 实在连不上时转发密文。
- **数据通路**：每对设备之间是一条 WireGuard 会话（boringtun）。
  - 虚拟地址直接配在 superNET 的 TUN 网卡上，`10.66.0.0/24` 路由进 TUN；
  - 这一段的包不进用户态协议栈，原样加密后发给对端；对端解密后原样写进它的 TUN；
  - 所以本机的远程桌面、共享等服务都能被访问。
  - **组网需要开 TUN 模式**（Windows 要管理员权限）。
- **一个 UDP 套接字复用所有用途**：WireGuard 数据、探测包、向协调服务查询地址、中继帧。打洞依赖“探测时用的端口”和“发数据的端口”是同一个。

### 选路（每个对端单独选，定期重测）

1. 收集对方的候选地址：局域网地址、IPv6 公网地址、协调服务看到的 IPv4 公网地址和端口。
2. 协调服务通知双方同时向对方所有候选地址发探测包（打洞）。哪条先通、延迟最低，就用哪条。
3. 优先级：局域网 > IPv6 直连 > IPv4 打洞 > 组内设备中继 > 服务器中继。
4. 直连不通时，看组内哪台设备同时和两边直连，并且两段延迟之和最低，由它转发。
5. 每 30 秒左右重新探测一次。网络变化（换 Wi-Fi、4G 切换）时立即重测；当前路径断了，自动降级到下一条。

### 中继

- 中继帧格式：`[标记][目标设备编号][WireGuard 密文]`。中继设备只按编号转发，解不开内容。
- 每台设备可以设置“允许为别人中继”：
  - 电脑默认开启；
  - 手机默认关闭，因为转发会耗流量和电量，用户可以手动打开。
- 服务器中继限速，保护 1C1G 服务器（默认每台设备 2 MB/s，总计 8 MB/s，可调）。
- 已知限制：服务器中继走 UDP。从你这里到服务器的 UDP 实测丢包约 25%，所以服务器中继只保证“能连上”，不保证快。

### 拓扑图

- 组网页面实时画出网内所有设备（每秒刷新），本机居中，服务器单独标出。
- 每条连线代表一对设备之间当前实际使用的路径：
  - 颜色区分路径类型：局域网、IPv6 直连、IPv4 打洞、经某台设备中继、经服务器中继、不通；
  - 线上标注延迟；
  - 线宽随当前流量变化。
- 经中继的连接画成折线，经过那台中继设备，并标出“由 B 中继”。
- 设备节点上显示名称、虚拟地址、在线状态、是否正在为别人中继。点一下可以看详情：候选地址、各条路径的探测结果、收发流量。
- 每台设备都会上报自己和其他设备之间的路径状态，协调服务汇总后下发。所以拓扑图里不只有本机的连线，别人之间的连线也能看到。

### 加入和管理

- 创建网络时生成邀请链接 `supernet-net://服务器:端口?k=邀请密钥&pin=证书指纹`。在客户端粘贴即可加入，协调服务分配虚拟地址。
- 设备的私钥只留在设备上；协调服务只保存公钥。
- 管理员设备可以查看成员、改名、踢出设备，也可以重置邀请密钥。

### 安全

- 设备之间用 WireGuard 端到端加密。协调服务和中继只看得到公钥、地址和密文。
- 信任边界是协调服务：它能决定谁是成员，所以必须跑在你自己的服务器上，控制通道固定证书指纹。
- 每个设备只放行来自虚拟网段、并且与发送方公钥对应的源地址，防止冒充。

### 现实情况

- 中国的家庭宽带和 4G/5G 上的 IPv4 往往是多层 NAT 或对称 NAT，IPv4 打洞经常失败。
- 但你的电脑有公网 IPv6（2409:…），国内移动网络普遍也有 IPv6，所以 IPv6 直连成功率高。不过路由器的 IPv6 防火墙可能拦截主动连入，同样要靠双方同时发包来打通。
- 两台设备在同一个局域网里时直接走局域网，不经服务器。

### 分阶段

| 阶段 | 内容 | 怎么验证 |
|---|---|---|
| G1 | 协调服务（成员、地址、探测、服务器中继）、加入链接、TUN 上的组网数据通路、界面里的成员列表 | 自动测试：进程内模拟多台设备和 NAT。真实测试：本机 Windows 加服务器上的一个无界面测试成员（公网直连） |
| G2 | P2P：候选地址、同时发包打洞、IPv6 直连、选路和降级、网络变化重测 | 自动测试：模拟锥形 NAT、对称 NAT、丢包。真实测试：需要两台在不同网络的设备 |
| G3 | 组内设备中继：选中继、限速、开关 | 自动测试：三台模拟设备，其中两台互相不通 |
| G4 | 跨平台成员：Android（M4）之后，用手机 4G 和家里电脑实测打洞和中继 | 真机 |

真实打洞测试需要两台在**不同网络**里的设备。比如家里的电脑和用 4G 的手机，所以要等 Android 端（M4）。MuMu 模拟器和电脑共用同一个网络，测不了打洞。
