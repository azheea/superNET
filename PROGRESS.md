# superNET 进度

验证记录分两类，分开写：自动测试（单元/协议/端到端）和真实程序或设备上的验收。没跑过的检查不写成通过。

## 2026-11-14（续三）：Linux 图形版、无界面服务器组网、网页控制台

### 测试环境

用户的 Mac 上用 Lima 2.3.0 起了一台 Ubuntu 24.04 arm64 虚拟机：
- Apple 虚拟化框架，6 核、8 GB；
- 只挂载 `~/supernet-build`；
- 没用 containerd。

这台电脑没装 WSL（装它要改 Windows 设置）；服务器只有 1 GB 内存还跑着 s-ui，都不适合编译 Tauri。

下载方面：
- Homebrew 不给预览版 macOS 27 提供 lima，改从 GitHub Releases 下载，SHA256 校验通过；
- GitHub 直连不通，所以在 Mac 上以普通用户另起了一个 superNET（只开本地代理，规则全部走节点）给下载用。这也验证了 superNET 当 HTTP 代理的用法。

### Linux 图形版

- `scripts/build-linux-app.sh` 生成 deb：应用 `/usr/bin/supernet-app`，加上 `/usr/bin/supernet-cli`。
- 在虚拟机里安装后，在 Xvfb 中运行并截图，界面完整、后端数据正常。
- 重构到 `supernet-control` 之后又构建、运行了一次，仍然正常。

### 无界面服务器组网

- 新增 `supernet join 邀请链接 [--name] [--install-service]`：生成密钥、写配置（600），装 systemd 服务。
- 新增 `--mesh-only`：只给组网网段建路由，不碰默认路由和 DNS，也不固定自己的套接字。
- 虚拟机实测：
  - join 加装服务一条命令完成，拿到 10.66.0.6；
  - 默认路由和 DNS 前后完全一致，普通上网照旧；
  - ping 服务器约 280 ms，ping Mac 约 2 ms，Mac ping 虚拟机约 1.9 ms；
  - 再次 join 沿用原密钥，地址不变。
- 观察到：服务重启后的十几秒里，到 Mac 的包不通，WireGuard 会话重建后恢复（10/10）。

### 网页控制台（`supernet --web`）

- 把桌面版的后端（24 个命令）从 Tauri 里抽成 `crates/supernet-control`，桌面版只剩薄包装；Android 的 VpnService 通过 `Vpn` 接口接入。
- `supernet --web [IP:]端口`：
  - 前端在编译时嵌进二进制；
  - `POST /api/<命令>` 接口复用同一套逻辑，必须带 Bearer 令牌（随机 24 字节，存在数据目录、权限 600），令牌通过链接的 `#token=` 交给前端，前端取下后马上从地址栏清掉；
  - 默认 127.0.0.1，改成公网地址会提示风险；
  - 回应带 CSP、nosniff、DENY 框架等头。
- `join --install-service` 默认开 127.0.0.1:9090，加 `--no-web` 关闭。
- 本机实测（Windows，代理模式）：
  - 不带令牌或令牌错误返回 401；
  - 浏览器里显示真实状态，切换模式、节点测速（2756 ms）都正常。
- 虚拟机实测：经 `ssh -L` 隧道在这台电脑的浏览器里打开服务器的控制台，组网页显示本机、服务器、MacBook（局域网直连 1 ms），以及离线的设备。
- 发现：虚拟机没有 IPv6，组网往 Mac 的 IPv6 候选地址发送失败。新加的发送失败统计能看到这一点（不影响使用，会走其他路径）。

## 2026-11-14（续二）：Mac 常驻组网，跨设备实测

- Mac 以“MacBook”加入组网（10.66.0.5）：配置写在 Mac 应用的配置文件里（旧的备份为 `profile.yaml.bak`），命令行版以 `--tun` 常驻运行（用户授权的免密 sudo，只限这个程序）。
- Mac 上：
  - 经 TUN 访问 ipify 显示 203.0.113.10，其余直连（贵阳移动）；
  - 系统解析返回假 IP；
  - Mac ping 服务器 10.66.0.1 能通，到美国的 UDP 线路丢包较多（4 个丢 3 个）。
- 电脑（`mesh-probe`，不开 TUN；这台电脑开着 Mihomo 的 TUN，会话也不是管理员）和 Mac：**局域网直连，13 ms**，两边上报一致。Mac 上报的候选地址：局域网、两个 IPv6、公网。
  - 第一次探测时显示过“服务器中继”，当时 Mac 刚启动；第二次稳定为局域网直连。
- 服务器 → Mac：经 wg0 ping 6/6，220–350 ms。
- **经组网 SSH 进 Mac**：以服务器为跳板连 Mac 的组网地址 10.66.0.5，登录成功（来源 10.66.0.1）。Mac 不在这个局域网时也能这样连。
- `mesh-probe` 现在会打印每个对端的候选地址、发送失败次数，以及每台设备上报的链路。
- 临时的电脑测试成员（10.66.0.6、10.66.0.7）已移除；协调服务重启后 Mac 仍在线。

## 2026-11-14（续）：macOS TUN 实测（真 Mac，用户授权免密 sudo 只限测试程序）

第一次 TUN 实测发现两个 macOS 专有问题，都已修好并复测通过：

1. **superNET 自己的连接全部 `Network is unreachable`**（DNS、Hysteria2、组网都不通）。套接字用 `IP_BOUND_IF` 固定到 en0，按 en0 作用域选路；en0 只有不带作用域的默认路由，TUN 的 0/1、128/1 加上后选路落到 utun 上，被内核拒绝。不开 TUN 时单独试 `IP_BOUND_IF` 正常，确认是 TUN 路由引起的。修复：开 TUN 时加一条 `route add -ifscope en0 default <网关>`，退出时删除（系统本来就有的不动）。
2. **组网 ping 不通**：utun 上第一个地址是 172.19.0.1，macOS 拿它当组网流量的源地址，服务器 wg0 只认 10.66.0.x，包被丢掉（服务器只收到握手）。修复：组网网段的路由加 `-ifa <组网地址>`。

另外，组网发送失败原来是静默丢弃的，现在计入状态（`send_errors`、`last_send_error`）；`tun-test` 在 macOS/Linux 上会打出路由，并分别用默认源地址和组网地址 ping。

复测结果：
- 代理 + TUN：
  - DNS 劫持正常（问 223.5.5.5 也返回假 IP）；
  - 直连百度 HTTP 200；
  - 经 Hysteria2 节点访问 ipify，显示 203.0.113.10；
  - “网络不可达”0 次。
- 组网 + TUN：
  - 加入组网用时 0.5–2 秒；
  - ping 服务器 10.66.0.1 两种源地址都通，220–290 ms；
  - 发送失败 0 次。
  - 有一次第一个握手在公网上丢了，WireGuard 按规范 5 秒后重发，前几个包因此等了 4–5 秒，另一次没有复现。
  - 到美国服务器的 UDP 有少量丢包（2/6），是线路本身的问题。
- 退出后：utun 路由、作用域默认路由、DNS 设置都撤掉了。
- 收尾：测试成员 10.66.0.5 已从协调服务和 wg0 移除（wg0 回到 3 个 peer），Mac 上的邀请链接、节点密码、设备密钥已删除。

## 2026-11-14：界面黑屏修复；在 Mac 上原生构建

### 点按钮黑屏（Windows、Android 都有）

- 现象：点开“出口节点”下拉框等控件后，整个窗口变成一片深灰，关掉弹层也恢复不了。
- 原因：`FluentProvider` 上写了 `className="root"`（高度 100%），而 Fluent 会把 provider 的 class 照抄到每个弹层（下拉列表、菜单、对话框、提示）挂在 `<body>` 上的挂载点。这个挂载点于是变成铺满全屏、带主题背景色的一层，盖住了整个应用。不是渲染器崩溃：当时页面的 DOM 完整，状态正常。
- 修复：provider 不再带 class，铺满窗口的高度只作用于 `#root > .fui-FluentProvider`。
- 验证：
  - 内置浏览器（Chromium）里修复前复现了黑屏，修复后下拉框、“添加节点”对话框都正常；
  - 弹层挂载点的高度变成 0。
  - Windows 版和 Android 版都已重新打包。Windows 版的 exe 没有实际点过（WebView2 的调试端口被 Tauri 的启动参数覆盖，开不出来）；MuMu 当时没开，新 APK 还没装上去验证。

### 在 Mac 上原生构建（Mac 换了地址 192.168.31.82，主机密钥和之前一致）

- 在用户目录装了 Rust（minimal，约 600 MB，没改 shell 配置）。
- `scripts/build-macos.sh` 跑通：superNET.app（包里带 `supernet-cli`）、dmg、命令行版，`codesign --verify --deep --strict` 通过。
- `ios/build.sh device` 用 Mac 自己的 cargo 编译 Rust 核心，再编译应用和扩展、签名、打 ipa，没有警告。
- 构建中发现并修掉的问题：
  - 从 Windows 提交的 `.sh` 没有可执行位，Mac 上 `Permission denied`：已在 git 里标为可执行。
  - 在 Windows 上 `git archive` 或检出时，`core.autocrlf` 会把文件转成 CRLF：脚本报 `bash
`，codesign 读不了权限文件。新增 `.gitattributes`，`.sh`、`.entitlements`、`.plist`、`.swift`、iOS 头文件一律 LF。
  - Mac 上 cargo 没设最低系统版本时，ring 按 iOS 27.1 编译：`ios/build.sh` 现在传 `IPHONEOS_DEPLOYMENT_TARGET`。
- 环境问题（不是我们的代码）：Mac 的系统解析缓存里卡着 static.crates.io 的失败记录，清缓存要 sudo，构建时改用 rsproxy.cn 镜像（只写在 Mac 上的构建副本里）。

## 2026-11-09（白天）：在真 Mac 上验证 macOS、iOS

用户提供了 BlueWonder 项目里连 Mac 的方式（SSH，MacBook Air M4，macOS 27，Xcode 27.1）。Mac 上开着 Shadowrocket（TUN + 系统代理），sudo 需要密码；磁盘只剩约 4 GB，所以不在 Mac 上装 Rust、不在 Mac 上编译 Rust，Mac 只用来运行和做苹果工具链的编译链接。

### macOS 实测

- 命令行版（Windows 上交叉编译的 `supernet-aarch64`）在 Mac 上直接能跑。
- 代理模式（Hysteria2 节点，规则 `ipify.org` 走代理，其余直连）：
  - 经 superNET 访问 api.ipify.org 显示 203.0.113.10；
  - 经 superNET 访问 myip.ipip.net 显示本地移动出口（直连）；
  - 进程内存约 14 MB，退出正常。
  - 注：出站流量又经过了 Shadowrocket 的 TUN（它占着默认路由），但上面的结果说明 superNET 自己的分流和 Hysteria2 隧道是通的。
- 组网（`mesh-probe`，Mac 和这台 Windows 电脑同时跑）：
  - 两边互相看到对方，走**局域网直连**，延迟 16–21 ms；
  - 到服务器（10.66.0.1）的路径从“不通”变成“公网直连”。
- 图形界面（Tauri）：
  - 在 Windows 上交叉编译、链接（Zig + Mac SDK 的 `.tbd` 存根），组成 superNET.app；
  - 在 Mac 上 ad-hoc 签名后能启动，窗口 1040×721，WebKit 的网页、GPU、网络进程都起来了，内存约 107 MB；
  - **界面内容没有亲眼确认**：SSH 会话没有屏幕录制和辅助功能权限，截不了图也读不到页面文字。
- TUN 模式：还没测（要 sudo 密码，且要先断开 Shadowrocket）。测试脚本已放在 Mac 的 `~/supernet-test/run-tun-test.sh`。

### iOS 实测

- `libsupernet_ffi.a`：在 Windows 上用 Zig 和 Mac 上拷来的真 iPhoneOS 27.1 SDK 头文件交叉编译（`scripts/build-ios-lib.ps1`）。
- 隧道扩展在 Mac 上用苹果的 swiftc 和链接器编译、链接：
  - **发现一个真问题**：iOS SDK 没有 `sys/kern_control.h`，原来的 Swift 代码找不到 `ctl_info`、`sockaddr_ctl`、`CTLIOCGINFO`。照 WireGuard iOS 的做法在桥接头文件里声明（`ios/PacketTunnel/PacketTunnel-Bridging-Header.h`）。
  - 修好后链接通过：Rust 核心没有未定义符号，没有警告。
- 新写了原生应用 `ios/App/SupernetApp.swift`（SwiftUI）：连接/断开、流量、组网地址、每个设备的路径和延迟、和电脑版同样布局的拓扑图；设置页填邀请链接、设备名、中继开关和代理配置（YAML）。设备密钥用 CryptoKit 生成 X25519。
- `ios/build.sh` 只用 swiftc 和 codesign 构建（不需要 Xcode 工程）：
  - `device`：应用 + 扩展 + `.ipa`，`codesign --verify --deep --strict` 通过，权限（packet-tunnel-provider、App Group）和 `NSExtension` 配置正确；
  - `simulator`：在 iPhone 17 模拟器（iOS 27.1）里跑了界面：示例状态的主界面（拓扑、设备列表）、设置页、未连接状态，都截图看过；修了拓扑图上延迟标签压住设备名的问题。
- 未验证：装到真 iPhone 上跑隧道（需要付费开发者账号）。

### 修掉的问题

- **协调服务**：`supernet-coord remove` 不带 `--wg` 时，服务器 wg0 上会留下被移除设备的 peer，被移除的设备仍能通过 wg0 连服务器。现在服务启动时会对照成员列表清理带 `# supernet-mesh` 标记的 peer（其他 peer 不碰），已加单元测试并部署；wg0 回到 3 个 peer，s-ui 正常。
- **macOS 打包**：命令行版 `supernet` 和应用 `superNET` 放在同一目录时，在不区分大小写的文件系统（Windows、macOS 默认的 APFS）上会互相覆盖。应用包里的命令行版改名为 `supernet-cli`。
- **macOS 的 TUN**：应用不能以 root 运行，所以打开 TUN 时直接给出可复制的 sudo 命令（带真实路径）；命令行版新增 `--tun`，sudo 运行时把数据目录里新建的文件交还给原用户。
- `tun-test` 的诊断输出原来只有 Windows 命令，现在 macOS 用 `netstat`/`ifconfig`/`scutil`，Linux 用 `ip`/`resolvectl`。
- 命令行统计行：Hysteria2 节点没有握手时间时显示“-”，不再是“-s”。

## 2026-11-09（夜间，自主推进）：拓扑图、Android 正式版、IPv6 组网、Linux、macOS

### 拓扑图

- 有服务器、其他设备数为奇数时，环形位置偏转 25°，避免设备和服务器连成一条竖线。
- “不通”的连线不再标字；其他标签沿连线的法向偏移，不压线。
- 画布加高到 470，最下方设备的地址不再被裁掉。
- 验证：`tsc` 通过；浏览器预览（模拟数据，5 台设备）截图正常。

### Android

- 前台服务：
  - VPN 建立后调用 `startForeground`，通知栏显示“superNET 已连接”和组网地址；
  - 声明 `foregroundServiceType="systemExempted"` 和相应权限；
  - Android 13 及以上申请通知权限，拒绝了也不影响 VPN；
  - 通知栏使用新画的图标。
- 正式版：
  - 用 keytool 生成 RSA 3072 签名密钥，存在 `local/android-release.jks`，口令在 `local/android-keystore.properties`，都不进 git；
  - Gradle 从这两个文件读取签名配置；
  - 代码混淆会删改类名，加了保留规则，否则 Rust 按类名找不到 VPN 插件。
- 构建脚本：
  - 会话有管理员权限时，Tauri 的符号链接能建成，整个流程直接成功；否则仍走手动复制。
  - 产物复制到 `dist/android`。
  - 修了一个问题：`-Targets x86_64,aarch64` 传进来是一整个字符串，现在会按逗号拆开。
- 实测（MuMu，正式版 `superNET-universal-release.apk`，23.6 MB）：
  - `apksigner verify` 通过，证书 CN=superNET；APK 里同时有 arm64-v8a 和 x86_64 两份库。
  - 正式版不能被调试，`run-as` 写不进配置，所以用默认的空配置测：界面上打开 TUN → 连接 → VPN 授权（我在模拟器里点的确定）。
  - 结果：tun0 建好；`SupernetVpnService` 以前台服务运行（`isForeground=true`）；没有崩溃，也没有找不到类。
  - 回到桌面 2 分钟后，VPN 和前台服务都还在。

### 组网 IPv6 直连

- 设备多开一个 `[::]` 套接字，两个套接字收到的包交给同一个处理函数，发包时按目标地址族选套接字。
- 上报本机的全局 IPv6 地址：用固定在物理网卡上的套接字 connect 到 `[2400:3200::1]:53` 取得，只要 2000::/3。
- 候选地址不再过滤掉 IPv6。
- 自动测试：新增“两台设备只能走 IPv6”的测试，路径是 `Ipv6`，数据送达。组网测试共 7 项，全部通过。
- **真实网络实测**：新增 `supernet mesh-probe`，只加入组网，不开 TUN、不改路由，定时打印到每个成员走的路径。
  - 服务器（2001:db8:20:700::2）和电脑（2001:db8:…）同时运行，都加 `--only-ipv6`，只允许 IPv6 直连。
  - 电脑看服务器上的探测成员：路径 `Ipv6`，约 200 毫秒，地址 `[2001:db8:20:700::2]:49689`。
  - 服务器上的探测成员看电脑：路径 `Ipv6`，212 毫秒，地址是电脑的公网 IPv6。
  - 双向都打通了，包括电脑这边路由器的 IPv6 防火墙。
  - 测完已从协调服务和 wg0 里移除两个探测成员，服务器上的邀请链接临时文件已清空；s-ui 正常。

### Linux（M5）

- 接口固定和网卡检测：
  - 用 `SO_BINDTODEVICE` 固定到物理网卡；
  - 默认网卡从 `/proc/net/route` 读，选 metric 最小的默认路由；
  - `/sys/class/net/<网卡>/type` 为 65534 的（tun、wg 等）拒绝使用；
  - 解析逻辑有单元测试。
- TUN：
  - `ip route add 0.0.0.0/1` 和 `128.0.0.0/1` 两条路由；
  - DNS 用 `resolvectl` 把所有域名的查询指向 superNET（`~.`），没有 resolvectl 时给出警告；
  - 组网地址用 `ip addr add` 加到网卡上；
  - 退出时删除路由，并用 `resolvectl revert` 还原 DNS；
  - 必须用 root 运行（检查 `geteuid`）。
- 系统代理：GNOME 用 `gsettings`，其他桌面提示“不支持”。
- 命令行：`supernet --profile` 在配置为 `tun: true` 时开启 TUN，并按配置加入组网。
- 交叉编译：
  - `scripts/build-linux.ps1` 下载 Zig 0.17.1（SHA-256 与官方清单一致），由 `tools/zigcc` 包装成 C 编译器和链接器。这个包装程序会去掉 Rust 的 `--target` 参数，因为 zig 不认识 Rust 的目标名，第一次就是因此失败的。
  - 得到 `dist/linux/supernet`，5.3 MB，静态 ELF，不依赖动态链接器。
- 实测（服务器 203.0.113.10，CentOS Stream 8，只开代理模式，不开 TUN）：
  - HTTP 代理和 SOCKS5 访问 example.com 都返回 200；
  - 常驻内存 2.4 MB；
  - 15 秒后按时退出；
  - 测试前后 s-ui 和协调服务都是 active。
  - `/tmp` 下留了 supernet、linux-smoke.yaml、supernet-smoke.log 三个文件。
- Linux TUN 实测：在服务器上建了一个独立的网络命名空间 `sntest`，主机的路由、防火墙和 s-ui 都不受影响：
  - 命名空间里用一对 veth 伪造了一条默认路由（192.0.2.1），给 superNET 当“物理网卡”；
  - `supernet --profile`（`tun: true`）建好了 superNET 网卡（172.19.0.1/30），并加上 0.0.0.0/1 和 128.0.0.0/1 两条路由；
  - 发给 172.19.0.2 和 8.8.8.8 的 DNS 查询都由 superNET 应答，返回假 IP 198.18.1.0；
  - TCP 连接 198.18.1.1:80 的握手被 TUN 接住；
  - 按时退出后 superNET 的路由全部撤掉；命名空间已删除；测试前后主机的默认路由和 s-ui 都正常。
- Linux 组网实测：又建了一个命名空间 `snmesh`，用 veth 连到主机，地址用测试专用的 192.0.2.0/24，不改任何防火墙或 NAT。协调服务和 wg0 都在主机上，发往 203.0.113.10 的包由主机本地处理。
  - 第一次加不进组网，原因有两个，都修了：
    1. **rp_filter**：RHEL 系默认是严格模式（`all=1`），superNET 自己的连接收到回包时，内核反查源地址发现路由指向 TUN，于是把回包丢掉。现在开 TUN 时把物理网卡的 rp_filter 临时设为宽松（2），退出时恢复；内核实际采用全局值和网卡值中较大的那个，所以不用改全局值。
    2. **协调服务的回包源地址**：服务器有多个地址时，回包可能来自另一个地址（这次是 192.0.2.1，而不是 203.0.113.10），设备端原来只认邀请链接里的地址。现在只要能用协调服务的公钥解开就接受，并记下它实际的来源地址；来自这个地址的中继帧也接受。
  - 还发现一个问题：命令行版只处理 Ctrl+C。`timeout`、`kill` 和 systemd 停止服务发的都是 SIGTERM，进程会被直接杀掉，rp_filter 和 DNS 设置不会还原。现在 SIGTERM 也走正常退出流程。
  - 修复后的结果：
    - 加入组网，分到 10.66.0.5，地址加到了 superNET 网卡上；
    - ping 服务器 10.66.0.1：4 个全部收到，延迟小于 1 毫秒；
    - ping MuMu 10.66.0.4：6 个全部收到，约 210 毫秒，经服务器中继。这是 Linux 设备和 Android 设备之间的组网；
    - SIGTERM 退出后，rp_filter 恢复为 0，superNET 网卡移除。
  - 清理：每次测试后都从协调服务和 wg0 里移除了测试设备 10.66.0.5，移除时短暂停了协调服务；wg0 回到 3 个成员；命名空间和 veth 都已删除；s-ui 和协调服务正常。
- **没验证**：
  - systemd-resolved 的 DNS 设置：CentOS 8 服务器上没有它；
  - 真实 Linux 桌面上的体验。

### macOS（M6，只有代码）

- 接口固定：`IP_BOUND_IF` / `IPV6_BOUND_IF`；默认网卡用 `route -n get` 查，utun、ipsec 开头的拒绝使用。
- TUN：网卡是 utunN；路由用 `route add`；DNS 用 scutil 的动态配置（`State:/Network/Service/superNET/DNS`），不落盘，启动时会清掉上次残留的。
- 系统代理：`networksetup`，对所有启用的网络服务生效。
- 构建：`scripts/build-macos.sh`，生成 .app、dmg 和命令行版。
- 验证：按 `aarch64-apple-darwin` 和 `x86_64-apple-darwin` 两个目标对 netstack、tun、sysproxy 做 `cargo check`，都通过。
- 在 Windows 上交叉编译并**链接**出 macOS 版命令行（`scripts/build-macos-cli.ps1`，用 Zig 当链接器）：
  - `dist/macos/supernet-aarch64`（4.4 MB）和 `supernet-x86_64`（4.8 MB），都是 64 位 Mach-O，CPU 类型正确，链接 `/usr/lib/libSystem.B.dylib`；
  - arm64 版带 ad-hoc 代码签名（`LC_CODE_SIGNATURE`），Apple Silicon 上可以运行；x86_64 版没有签名，Intel Mac 不需要。
  - 遇到两个问题，都在 `tools/zigcc` 里解决了：
    - Zig 的 macOS 系统库桩里没有 libiconv，所以去掉 `-liconv`；
    - rustc 在 Windows 上会把很长的链接参数写进响应文件（`@文件`），包装程序现在会展开、过滤，再写回给 Zig。这部分有单元测试。
  - 改了包装程序之后，Linux 版也重新编译过，仍然成功。
- **没有在 Mac 上运行过**：图形界面应用要在 Mac 上用 `scripts/build-macos.sh` 构建。

### iOS（M7，只做了 Rust 部分的准备）

- 按 `aarch64-apple-ios` 目标对 netstack、tun、sysproxy、mesh 做 `cargo check`，通过。
  - 修了两处：iOS 原来没有连接固定和找默认网卡的实现，现在连接固定和 macOS 一样用 `IP_BOUND_IF`，找默认网卡返回“不支持”（iOS 的路由由 Network Extension 管）；
  - iOS 和 Android 一样，不用桌面版的建网卡流程，将来走 `start_fd`，接管 Network Extension 的 utun 描述符。
- 新增 `crates/supernet-ffi`：把 Rust 核心包装成带 C 接口的静态库，头文件是 `ios/supernet.h`。调用顺序和 Android 一样：
  1. `supernet_prepare` 启动引擎并加入组网；
  2. `supernet_mesh_address` 取组网地址，写进隧道配置；
  3. `supernet_attach_tun` 接管隧道的描述符；
  4. 运行中可用 `supernet_status_json` 取状态，最后用 `supernet_stop` 停止。
  - Windows 上的单元测试通过：启动、读取状态 JSON、停止都正常，配置路径错误时返回 NULL。
  - 按 `aarch64-apple-ios` 目标做 `cargo check` 通过，ring 的 C 代码也编译过。为了在没有苹果 SDK 的情况下编译，`tools/zigcc` 加了开关 `SUPERNET_ZIG_NO_SYSROOT`，借用 Zig 自带的 arm64 Darwin 头文件，这只用于编译检查。
- 新增 `ios/PacketTunnel/PacketTunnelProvider.swift`：
  - 先加入组网，再设置隧道：地址是 172.19.0.1/30 加上组网地址，IPv4 和 IPv6 默认路由，所有域名的 DNS 都指向 172.19.0.2；
  - 用 WireGuard iOS 版的办法找到 utun 描述符，交给 Rust 核心；
  - 应用可以通过 provider message 读取状态 JSON。
  - 在 Mac 上怎么接入 Xcode 工程，写在 `ios/README.md`。
- **没做**：在 iOS 上构建和运行，以及应用这边的配套代码（写入 App Group 里的配置、启停隧道）。需要 Mac 和付费的 Apple 开发者账号，因为 Network Extension 权限只发给付费账号。Swift 代码还没有编译过。

### 回归实测（新调试版，含前台服务和 IPv6 套接字）

- MuMu：VPN 建立，tun0 上有 172.19.0.1/30、10.66.0.4/24 和 fdfe:dcba:9876::1/126；前台服务在运行。
- 电脑以管理员身份运行 `tun-test --mesh`：
  - 加入组网，分到 10.66.0.3，耗时 2.2 秒；第一次加入请求可能丢了，2 秒后重试成功。
  - ping MuMu：6 个回 6 个，路径是局域网直连，26 毫秒。
  - ping 服务器：6 个回 5 个。
  - 结束后没有残留路由。
- MuMu 里的 Chromium 打开 https://api.ipify.org，显示 203.0.113.10。
- 自动测试：`cargo.ps1 test --workspace --exclude supernet-app` 全部通过。其中组网 7 项、核心 16 项、Hysteria2 4 项、netstack 5 项；端到端测试 2 项（含 TUN）；WireGuard 3 项，另有 1 项默认忽略；系统代理 2 项；协调服务 1 项。

### NAT 打洞实验：模拟真手机走 4G 的情况

真手机走 4G 要靠你，所以先在服务器上用网络命名空间搭了一个实验环境（`scripts/nat-lab.sh`）：
- 两台“设备”各自躲在一个“NAT 路由器”命名空间后面，互相不在同一个局域网；
- NAT 规则只写在路由器命名空间内部，主机只在两条 veth 之间转发，主机的防火墙和路由都没改；
- 两台设备都运行 `mesh-probe`，看它们之间走哪条路。

过程中发现并修了三个问题：
1. **协调服务的回包源地址**：协调服务原来监听 0.0.0.0，回包从 192.0.2.9 发出，而不是设备请求的 203.0.113.10，NAT 无法反向转换，设备因此加入不了网络。服务器有多个 IP、设备又在 NAT 后面时，真实环境也会这样。现在协调服务直接监听公网地址（`--listen 203.0.113.10:19190`），已重新部署。
2. **nft 版本差异**：服务器上的 nft 较老，不认单行写法，实验脚本改成多行。
3. **打洞卡住（核心问题）**：连接跟踪表证实了 Linux 式 NAT 的经典冲突：
   - B 的探测先到了 NAT A，NAT A 为它建了一条“没有回应”的记录；
   - A 随后发往 B 的包与这条记录冲突，被换了外部端口（60357 变成 12588）；
   - NAT B 只认 60357，把 12588 来的包丢掉；双方的探测不断刷新那条记录，所以永远打不通。
   - 修复：打洞前先发几个低 TTL 的“预热”包（默认 TTL 2 到 5），它们只够穿过自己这侧的 NAT 并建好映射，在到达对方 NAT 之前就被丢弃；0.5 秒后再发正常的探测包。
   - 只对公网 IPv4 候选地址这样做：IPv6 不做地址转换，没有端口冲突；局域网也不需要。
   - 改 TTL 和发包都加锁串行执行，正常数据包不会被设成低 TTL。
   - TTL 列表可以用环境变量 `SUPERNET_PUNCH_TTL` 调整。实验链路只有 3 跳，所以实验里设成 2。

修复后的结果：
- **两边都是普通 NAT**：打洞成功，走直连，双方看到的都是对方 NAT 的公网侧地址（192.0.2.14:46683 和 192.0.2.10:52649）。
- **B 是端口随机的对称 NAT**（模拟很多 4G 网络）：打洞不可能成功，自动退回服务器中继，符合设计。
- 回归：电脑和 MuMu 之间仍走局域网直连，2 毫秒；组网测试 7 项全部通过。
- 清理：每轮测试后都从协调服务和 wg0 移除了测试设备，wg0 回到 3 个成员；命名空间都已删除；s-ui 和协调服务正常。

**仍然没验证**：真手机在真实 4G 网络上打洞。默认 TTL 列表 2 到 5 是按“对方 NAT 距离远多于 5 跳”估计的，真实运营商网络还要实测。

### 其他

- 我用 Python 改 PowerShell 脚本时，有两次 `\a`、`\r` 被当成了控制字符，路径被破坏。都已修好，并检查过所有脚本，没有残留。
- 应用里“需要管理员权限”的提示按平台区分：Windows 提示点“以管理员身份重启”，macOS 和 Linux 提示用 sudo 运行命令行版。

## 2026-11-09（续）：M4 Android 第一版 + 设备之间组网实测（Claude，本地）

### Android

- 环境（都下载自官方源）：
  - Android SDK：cmdline-tools（SHA-1 校验过）、platform-tools、平台 34 和 37.0；构建时 Gradle 自动装了 build-tools 36；接受了 SDK 许可；
  - Rust 目标：x86_64、armv7、i686 的 Android 目标；
  - NDK 27.2 和 JDK 17 原来就有。
- `tauri android init` 生成了工程 `app/src-tauri/gen/android`。现在纳入 git，自动生成的部分仍忽略。
- Kotlin：
  - `SupernetVpnService`：建立 VPN。地址 172.19.0.1/30 和 fdfe:dcba:9876::1/126，DNS 指向 superNET，IPv4 和 IPv6 全部接管；把 superNET 自己排除在 VPN 之外，防止回环；组网地址一起写进 VPN 配置。
  - `VpnPlugin`：请求授权（prepare）、建立 VPN（establish，返回网卡描述符）、停止（stop）。
- Rust：
  - `supernet-tun::start_fd` 接管 VpnService 的描述符；桌面版和 Android 版共用收发和组网分流代码。
  - 应用在 Android 上的开启顺序：请求授权 → 先加入组网拿到地址 → 建立 VPN → 接管网卡并接上组网。组网设置变化时重建 VPN。
- `scripts/build-android.ps1`：Windows 没开开发者模式时不允许建符号链接，Tauri 打包会失败。脚本改为自己把 Rust 库复制进工程，再用 Gradle 打包。
  - 得到 x86_64 调试版 APK，225.7 MB，因为没剥离调试信息。

### MuMu 模拟器实测（Android 12，x86_64）

- 安装、启动正常，界面和桌面版一致。配置经 `adb exec-in run-as` 写入应用私有目录，权限设为 600，不留临时文件。
- 点“连接”后弹出系统的 VPN 授权框，你点了确定。系统日志显示 “Established by app.supernet.client on tun0”：
  - tun0 上有 172.19.0.1/30、fdfe:dcba:9876::1/126，以及组网地址 10.66.0.4/24（加入组网后拿到的）；
  - superNET 自己的 uid 被排除在 VPN 之外。
- 注意：在 MuMu 上，adb shell（uid 2000）也不经过 VPN，所以 shell 里的测试不能算数。
- 模拟器里的 Chrome 经 VPN 打开 https://api.ipify.org，显示 203.0.113.10：按规则经实测HY2 出去，HTTPS 的 SNI 嗅探也正常。
- 组网页：拓扑图里 MuMu 和服务器之间是公网直连；离线的设备画成虚线。

### 设备之间组网（电脑 `tun-test --mesh` ↔ MuMu）

- 第一次：电脑 ping MuMu 10.66.0.4，6 个回 3 个，约 390 毫秒，走服务器中继。
  - 发现 bug：电脑开着 TUN 时，“本机局域网地址”的探测走进了 TUN，于是把自己的组网地址 10.66.0.3 当成候选地址上报了。
  - 修复：探测改用固定在物理网卡上的套接字；上报、接收和学习候选地址时，都排除组网网段、TUN 的 /30 和假 IP 段。组网测试 6 项仍全部通过。
- 修复后（这次在管理员会话里直接运行）：MuMu 走**局域网直连**，延迟 3 毫秒，ping 6 个回 6 个。
  - 打洞过程：MuMu 的探测包穿过模拟器 NAT 到达电脑，电脑学到了 MuMu 的映射地址 192.168.31.9:59152，再往回探测，打通。
  - 电脑 ping 服务器 6 个回 5 个。自检结束后，网卡和路由都撤干净了。

### 还没做

- 用两台在不同网络里的真机测打洞（比如家里电脑和 4G 手机）；
- Android 版的前台服务和通知（目前系统内存紧张时可能被回收）；正式版签名；arm64 真机安装包；
- 拓扑图在设备很少时，标签会和连线重叠。

## 2026-11-09：M2.5 虚拟组网 G1（Claude，本地，未提交，未部署）

设计和你的决定见 `docs/DESIGN.md` 第 15 节：
- P2P 优先，连不上时由组内设备中继，服务器兜底；
- 沿用 10.66.0.0/24，服务器 10.66.0.1 也是成员；
- 协调服务用 UDP 19190；
- 所有设备默认允许中继；
- 实时拓扑图。

### 做了什么

- `supernet-mesh`（新）：
  - `proto`：报文格式。控制消息和探测包用 X25519 + XChaCha20-Poly1305 加密，带递增时间戳防重放；中继帧里只有 WireGuard 密文；邀请链接格式 `supernet-net://`。
  - `coord`：协调服务。负责成员和地址分配、告诉设备它的公网地址、通知双方打洞、兜底中继（每台设备 2 MB/s、总计 8 MB/s）。路径一变就推送给其他设备；状态存在 JSON 文件里。
  - `device`：设备端。一个 UDP 套接字承载所有用途：
    - 每个对端一条 boringtun 会话；
    - 探测各候选地址并测延迟，选路：局域网 > IPv6 > 公网 IPv4 > 设备中继 > 服务器中继；
    - 不通时请协调服务通知对方打洞；
    - 为别人中继时，只转发双方都直连的设备的帧；
    - 丢弃源地址和对端不符的包。
- `supernet-coord`（新）：服务器上运行的协调服务。
  - 子命令：`run`、`invite`、`reset-invite`、`members`、`remove`；
  - 加 `--wg wg0` 时，新设备会自动登记到 wg0 和 `/etc/wireguard/wg0.conf`；
  - 依赖里没有 C 代码，可以从 Windows 交叉编译成 Linux 静态程序（`scripts/build-coord.ps1`）。部署脚本是 `scripts/deploy-coord.ps1`。
- TUN：发往组网网段的包原样交给组网，收到的包写回网卡；加入网络后把组网地址加到 superNET 网卡上。
- 应用：
  - 配置新增 `mesh` 段；
  - 新命令：加入、修改、退出、查看状态；
  - 开 TUN 后自动启动组网；
  - 新增“组网”页：加入表单、开关、成员表、实时拓扑图。拓扑图的连线按路径类型着色，线宽和流动速度随流量变化，中继连线弯过中继设备，正在中继的设备挂“中继”标记，点设备看详情。

### 自动测试（本机，进程内）

- `supernet-mesh` 6 项全部通过：
  - 两台设备走局域网直连，冒充其他地址的包被丢弃；
  - 禁止直连时经协调服务中继，900 个包至少到达 890 个（发送速度在限速以内）；
  - A、C 互相不能直连时自动改由 B 中继，B 的中继计数大于 0；拓扑在 8 秒内同步到 B；
  - 无效邀请被拒绝；协调服务重启后公钥、邀请和成员地址都不变；
  - 邀请链接往返解析；密钥不对或报文被篡改时解不开。
- `supernet-coord` 1 项：wg0.conf 的成员块解析和删除。
- 前端：`tsc --noEmit` 通过。浏览器预览（模拟的 5 台设备）：组网页、拓扑图、图例、设备表显示正常。

### 部署（203.0.113.10）

- `scripts/build-coord.ps1` 在 Windows 上交叉编译出 Linux 静态程序：1.2 MB，没有 C 代码。下载编译目标时网速只有约 40 KB/s。
- `scripts/deploy-coord.ps1` 把协调服务装成 systemd 服务 `supernet-coord`（内存上限 64M），先把 `wg0.conf` 备份为 `wg0.conf.before-mesh`。
  - 运行中常驻内存约 1.2 MB，监听 UDP 19190；
  - 服务器成员 10.66.0.1 读取正确；
  - s-ui 和现有的 wg0 成员 10.66.0.2 没动。
- 修了两个安全问题：
  - 状态文件里有协调服务的私钥，权限改成 600；
  - 日志里不再写邀请密钥。第一次启动时的日志里已经写过一次，所以重置了邀请密钥。
  - 新的邀请链接只存在 `local/mesh-invite.txt`（已被 git 忽略）。

### 第一次实测：被 Clash 的 TUN 挡住

- 本机实测时 Clash（mihomo）开着 TUN 模式，虚拟网卡“Mihomo”占着默认路由和 DNS。
- superNET 把它当成了物理网卡，两个 TUN 互相绕圈，系统缓冲区耗尽（错误 10055）。
- 自检按时退出，superNET 的网卡和路由都撤干净了；你的网络一直由 Clash TUN 提供，没受影响。
- 修复：开启 TUN 前检查默认路由所在的网卡。如果它是虚拟网卡或隧道（别的 VPN/TUN），就拒绝开启，并提示先关闭。应用和 `tun-test` 都走这个检查；在本机（Mihomo TUN 开着）验证过会给出提示。
- 第一次组网实测因此没做成。

### 真实组网测试（关掉 Clash TUN 后，`tun-test --mesh`，管理员）

- 本机用邀请链接加入：261 毫秒加入成功，分到 10.66.0.3/24；协调服务看到的本机公网地址是 198.51.100.162:33983。成员列表：10.66.0.1 服务器，10.66.0.3 本机。
- 组网地址加到 superNET 网卡后，用系统自带的 ping 测 10.66.0.1（经组网，走服务器的内核 WireGuard）：6 个包回 5 个，延迟 219～241 毫秒。丢包和这条线路本来的 UDP 丢包一致。
- 对端状态：到服务器是直连，7 秒前握过手；TUN 错误 0。
- 服务器那一侧：
  - wg0 新增成员 10.66.0.3，端点就是 198.51.100.162:33983，20 秒前握过手；
  - `wg0.conf` 里写入了 `# supernet-mesh AZHE` 这一段，重启后也会保留；
  - 协调服务常驻内存 1.2 MB。
- 自检退出后网卡和路由都撤干净了。

### 还没做

- 在应用界面里加入网络、看拓扑图（要重新打包正式版）；
- 设备之间直接互访（要第二台设备）；
- 跨网络打洞（要等 Android 端，用手机 4G 测）；
- IPv6 直连（目前设备只用 IPv4 套接字）；
- 管理员在客户端里踢人（目前在服务器上用 `supernet-coord remove`，之后要重启服务）。

## 2026-11-08（续三）：M2 Windows TUN 模式（Claude，本地，未提交）

### 做了什么

- 新增 crate：
  - `supernet-netstack`：smoltcp 用户态协议栈，接收任意目标地址的 TCP，原样取出 UDP；另有 `sysnet`，用 IP_UNICAST_IF 把 superNET 自己的套接字钉在物理网卡上，避免流量绕回 TUN。
  - `supernet-tun`：基于 wintun（tun-rs）。网卡 `superNET` 地址 172.19.0.1/30，DNS 172.19.0.2。路由 0.0.0.0/1、128.0.0.0/1 和各物理网卡的 DNS /32，都用 `store=active` 添加，进程退出就消失。
- 核心：
  - 假 IP DNS（198.18.0.0/15），劫持所有发往 53 端口的查询；
  - TCP 用 TLS SNI / HTTP Host 嗅探出域名；
  - UDP 按会话转发，空闲 60 秒回收；
  - Hysteria2 UDP。
- 应用：TUN 开关和“以管理员身份重启”。`build-app.ps1` 打包 wintun.dll，下载时校验哈希和 WireGuard LLC 签名。
- 命令行新增 `supernet tun-test`：限时运行，跑一组探测，到时自动退出并撤掉路由。另有看门狗线程，超时强制退出。

### 第一次真实测试断网：查明原因并修复

- 现象：开启 TUN 后 DNS 和网页全部不通，本机断网，直到关闭 superNET。
- 原因是**组播风暴**：
  - Windows 往 TUN 发 SSDP（1900）、mDNS（5353）、LLMNR（5355）组播包；
  - superNET 把它们按“直连”转发出去；
  - 组播不受 IP_UNICAST_IF 约束，按组播路由又回到 TUN，越转越多。
  - `tun-test` 实测 2 秒内收了 144,072 个包，系统套接字缓冲耗尽（错误 10055）。
- 修复：网络栈直接丢弃组播、广播、链路本地和未指定地址的包，新增单测。修复后 45 秒内一共只收到约 2,000 个包。

### 真实测试（本机 Windows，管理员，`tun-test`）

修复后跑了 4 轮，每轮都正常退出，网卡和路由撤干净（之后检查过：没有 superNET 网卡，没有 0.0.0.0/1 路由）。最后一轮的结果：

- 向 172.19.0.2 查询 www.baidu.com，1 毫秒内得到假 IP；发往 223.5.5.5 的查询也被劫持，同样拿到假 IP。
- HTTP 直连 www.baidu.com：200 OK，约 100 毫秒。
- HTTP 经节点访问 api.ipify.org（规则 → 代理 → 实测HY2）：200 OK，正文 **203.0.113.10**，约 0.5 秒。
- 引擎测速：实测HY2 1.2～2.8 秒，实测节点（WG）0.9～6 秒。
- TUN 收发错误计数：0。

### 正式版应用验收（本机 Windows，Radmin 已停用）

- 用 `build-app.ps1` 打包的 `dist/windows/superNET.exe`，以管理员身份启动（测试配置 `local/app-real`，开启 TUN，自动连接）：
  - 网卡 superNET 和 0.0.0.0/1 路由都建好了；
  - 系统解析 www.baidu.com、api.ipify.org 拿到假 IP（16 毫秒、1 毫秒）；
  - 不经代理的 curl：HTTP 和 HTTPS 访问百度都是 200；api.ipify.org 的 HTTP 和 HTTPS 都返回 203.0.113.10；https://github.com 返回 200（经节点）。
- 你在概览页关掉 TUN 开关后：网卡和路由都没了，解析恢复为真实地址（含 IPv6），HTTPS 访问百度 200。
- 没测：断开或退出时自动撤除；UDP 游戏等实际应用。

### TUN 启动后系统解析会卡：原因已查明

- 现象：启动后的前 10 到 25 秒，系统解析（getaddrinfo）每次都要 7 到 12 秒；之后恢复到 1 毫秒。DNS 跟踪显示，Windows 发来的 A 查询 superNET 都在 1 毫秒内应答了。
- 不开 TUN 时本机解析一样慢：A 记录约 7 秒，AAAA 约 11 秒。逐个测服务器：
  - Radmin VPN 网卡（接口跃点 1）上的 114.114.114.114 超时；
  - 以太网 2 上的 210.40.0.33 拒绝查询；
  - 192.168.31.1、223.6.6.6、路由器的 IPv6 DNS 都在 30 毫秒以内。
- 给 TUN 加了私有 IPv6 地址 fdfe:dcba:9876::1/126 和 IPv6 DNS ::2（tun-rs 一次只能设一种地址族，IPv6 DNS 用 netsh 设置）。实测之后：
  - Windows 的 A 和 AAAA 查询都发给 superNET，都当场应答了；
  - 但启动后约 16 秒内发起的系统解析，仍然每次正好卡 12 秒，期间 Windows 在重发同一个查询；
  - 同一时间用 nslookup（自带套接字）查 172.19.0.2，31 毫秒就拿到假 IP；
  - Windows 网络识别（NLA）在启动后 2 秒就已完成（IPv4 Internet），可以排除。
- **原因已证实**：你停用 Radmin VPN 网卡后：
  - 不开 TUN 时系统解析 30～55 毫秒（之前 7～11 秒）；
  - 开 TUN 后 3 秒的第一次系统解析 1 毫秒，全程没卡；
  - 其余探测全部通过（直连 200；经 HY2 出口 203.0.113.10；TUN 错误 0）。
- 卡顿是 Windows DNS 服务在等 Radmin VPN 网卡上不通的 114.114.114.114。那个查询走 Radmin 网卡，TUN 劫持不到。
- 做了 DNS 防泄漏（WFP 动态会话，`crates/supernet-tun/src/wfp.rs`）：
  - TUN 期间，53 端口的查询只放行三种：TUN 网卡上的、superNET 自己进程发的、回环；其余一律拦截。
  - 规则由 Windows 在 superNET 进程退出（包括崩溃）时自动删除。
  - 装不上时 TUN 照常运行，日志里给出警告。
- 实测（Radmin 停用）：
  - 别的进程绕过 TUN 去问路由器的 IPv6 DNS，被拦截（之前 9 毫秒就有应答）；
  - 其余探测全部通过。
- 实测（Radmin 启用；此时不开 TUN 解析每次 12 秒）：
  - 防泄漏已启用，拦截生效；
  - **但卡顿没有消失**：TUN 启动后约 21 秒内发起的系统解析仍然卡住，之后 2 毫秒；
  - 直连、经 HY2 出口（203.0.113.10）、WG 测速都通过。
- 新判断（**未证实**）：
  - 12 秒正好是 Windows DNS 的默认超时总和（1+1+2+4+4）；
  - Radmin VPN 和 superNET 的接口跃点都是 1，Windows 可能把 Radmin 当成首选网卡，一直等它，等满 12 秒才采用 superNET 早已给出的应答；
  - 被防火墙拦截的查询，Windows 并不会因此提前放弃等待。
- **处理决定（用户）**：永久停用 Radmin VPN 网卡，superNET 不再为它另做处理（不做 NRPT）。WFP 防泄漏保留。已知限制：别的电脑上如果也有一块接口跃点很低、DNS 又不通的网卡，同样会出现启动后十几秒的解析卡顿。
- 试过“先只接管假 IP 段，等系统 DNS 接受应答后再接管全部”的分阶段启动：启动要多等约 20 秒，接管后照样会卡，已撤回。
- 另一个已知缺口：目前不接管 IPv6 路由，IPv6 流量会绕过 TUN 直接出去。

## 2026-11-08（续二）：M3.5 原生 Hysteria2（Claude，本地，未发布）

### 做了什么

- 新增 `crates/supernet-hy2`：按官方协议文档实现 Hysteria2 客户端。
  - 基于 QUIC + TLS 1.3，ALPN 为 h3；用 HTTP/3 发 `/auth` 认证，返回 233 表示通过；
  - 每个 TCP 连接对应一条 QUIC 流（0x401 请求），所有连接复用一个 QUIC 连接，连接断开后自动重连；
  - 拥塞控制用 BBR，`down_mbps` 通过 `Hysteria-CC-RX` 头告诉服务器。
- 证书校验：
  - 默认按正常方式校验；
  - 自签证书用 `pin_sha256` 固定证书指纹；
  - `insecure` 必须明确写出来；在应用里导入只带 `insecure=1` 的链接时，会读取当时的证书，自动改成固定指纹。
- 节点类型 `hysteria2`：可以导入 `hysteria2://` / `hy2://` 分享链接，也能导出；遇到 obfs 会明确报不支持。界面会显示 Hysteria2 标记。
- `supernet pin-cert host:port [sni]`：打印服务器证书的 SHA-256。

### 在服务器上发现的问题

s-ui 的 Hysteria2 入站通过 ACME 自动申请证书，证书域名是 **hy2.example.com**。但 s-ui 给出的分享链接和你 Clash 里的配置写的都是 testhy3.example.com，用这个名字握手时服务器找不到证书，会返回 TLS 告警 80，所以 Clash 里的 `hysteria2-19188` 实际连不上。superNET 用 `hy2.example.com:19188`，证书能正常校验。

### 测试

- 自动测试全部通过：
  - Hysteria2 在本地测试服务器上做 1 MiB 回显 3 轮，连接被复用；
  - 证书指纹不符时拒绝；自签证书在正常校验下拒绝；认证失败（返回 404）时报错；目标连不上时报错；
  - 链接解析和导出的往返一致。
- 真实服务器：经原生 Hysteria2 下载 20 MB 两次，3.8 MB/s 和 4.4 MB/s；同一时间你的 Clash Auto 是 2.3 MB/s。出口 IP 是 203.0.113.10，github.com 打开用时 2.1 秒。
- 30 分钟浸泡测试：**按你的要求在第 7 分钟停了，没有完成**，脚本已删除。停之前的采样：
  - 客户端内存 14–34 MB；
  - 服务器可用内存 292–298 MB，负载 0.00–0.43，连接跟踪 176–212 个；
  - s-ui 内存 183–187 MB；
  - wg0 一直正常。
- **未验证**：界面改动只做了类型检查，没有重新编译安装包，也没有看过界面效果；在界面里导入时自动固定证书这一步还没有实际点过。

## 2026-11-08（续）：M3 真实节点 + SOCKS5 上游节点（Claude，已装到 203.0.113.10）

### 服务器

- 203.0.113.10 实际是 **CentOS Stream 8**（内核 4.18，770 MB 内存，没有 swap，KVM），同机运行 s-ui（TCP 2095 / 2096 / 52541，UDP 19188 / 28101）。
- 安装脚本 `node/install.sh` 改动：
  - 支持 EL 8/9：从 ELRepo 装 `kmod-wireguard`；从 EPEL **只下载 `wireguard-tools` 这一个包**。启用整个 EPEL 源时，dnf 加载软件列表要约 300 MB 内存，在这台机器上被系统因内存不足杀掉。被杀的只有 dnf，s-ui 没受影响；中途装上的 `epel-release` 已删除。
  - 支持 firewalld；
  - 共存检查：端口被占用或子网冲突时停止安装、不做任何改动；
  - 检测到 s-ui / sing-box 时说明只新增哪些东西。
- 部署：
  - `scripts/setup-ssh.ps1` 生成专用部署密钥，放在 `local/ssh`；
  - `scripts/deploy-node.ps1` 负责上传并安装。中途修过两个问题：PowerShell 5.1 按本地编码读脚本导致中文乱码；路径拼接写错。
- 服务器现状：
  - wg0 在 UDP 51820 上运行，开机自动启动；
  - 防火墙规则只在独立的 `inet supernet` 表里；
  - 没有 SELinux 拦截；
  - 内存还剩约 290 MB 可用；
  - 已添加一个客户端“测试电脑”（10.66.0.2）。

### 实测：这条线路上 UDP 被限速

结论见 `docs/DESIGN.md`“实测结论”一节。WireGuard 直连约 57 KB/s，下行约 25% 丢包；经 Clash 的 TUIC 或 vless 转发也只有 0.3–35 KB/s。真正可行的是原生实现能扛丢包的加密 QUIC 协议（M3.5：Hysteria2 / TUIC）。

- **SOCKS5 上游节点和 WireGuard 的 `via`（经 SOCKS5 转发）曾实现并测过，按你的要求已全部删除**：SOCKS5 是明文协议，出口只用加密传输。
  - 期间的实测：经本机 Clash 约 1.37 MB/s；`via` 在这条线路上不提速。
  - 那次 30 分钟浸泡测试走的就是 SOCKS5 节点，所以第 2 分钟就停了，**没有完成**。停之前服务器剩余内存约 292 MB，s-ui 182 MB 没变化，wg0 正常。
- **保留：直连 DNS 改为并发查询**。系统 DNS 冷查询 qq.com 实测要 11 秒，现在同时问所有上游，取最先返回的结果。你的配置里用的是 system + 223.5.5.5 + 119.29.29.29。
- **保留：新增无界面命令行 `supernet`**（`crates/supernet-cli`），用于浸泡测试和 Linux 服务器。
- 测试期间你在 Clash Party 里加了一个 JavaScript 覆写（`tuic-28101` 用 quic 模式，203.0.113.10 走 tuic-28101）。它现在已经没用了，可以关掉。

### 自动测试

删除 SOCKS5 相关代码后，全部测试重新跑过（结果见下一次提交说明）。

## 2026-11-08：M1 核心 + Windows 系统代理模式（Claude，本地，未发布）

### 做了什么

- **工程**：Cargo workspace + Tauri 2 应用。
  - 这台机器没有 Visual Studio，用 windows-gnu 工具链加 llvm-mingw 构建：`scripts/cargo.ps1` 设置环境，`scripts/build-app.ps1` 打包到 `dist/windows/`。
  - llvm-mingw 目前借用 starsavior 仓库 `local_state/launcher-toolchain` 下的那份，可以用 `SUPERNET_MINGW` 改指别处。
- **`supernet-wg`**：用户态 WireGuard（boringtun 0.7 + smoltcp 0.14）。
  - 提供 TCP 连接、TCP 监听、UDP；同一份代码既能当客户端，也能当服务端。
  - UDP 收发缓冲设为 4 MiB；发送缓冲满时先排队，不丢弃。
  - 新增丢包计数（`TunnelStats.drops`）和最近一次错误，方便排查。
- **`supernet-core`**：
  - 配置：YAML；
  - wg-quick 配置和 `supernet://` 链接导入导出；
  - Clash 兼容规则引擎：DOMAIN / SUFFIX / KEYWORD、IP-CIDR(6)、GEOIP、DST-PORT、RULE-SET（本地文件）、MATCH；
  - DNS：直连域名用本地 DNS，走节点的域名经隧道用节点的 DNS 解析；
  - HTTP 和 SOCKS5 共用一个端口；
  - 规则 / 全局 / 直连三种模式，策略组；
  - 连接列表、流量统计、日志、节点测速、规则测试。
- **`supernet-sysproxy`**：Windows 系统代理。修改前先备份原设置，断开或退出时恢复；如果上次崩溃留下了备份，启动时先恢复。
- **`supernet-testnode`**：不需要 root 的本地 WireGuard 测试节点，附带端到端测试。
- **界面**（React + Fluent UI）：概览、节点、规则、连接、日志、设置六页。

### 隧道内 TCP 卡顿：查明原因，打了补丁

这是本轮最重要的一项。

**现象**：端到端测试大约每 3 次有 1 次卡满 60 秒。压力测试（4 MiB 回显，40 轮）里常见 1 / 3 / 7 / 13 秒的停顿，偶尔超过 20 秒。

**排查**：
1. 给隧道加了丢包计数：网络上一个包都没丢，两端收发字节数一致，所以问题出在 TCP 协议栈内部。
2. 用带隧道标记的 smoltcp 追踪日志定位到具体原因，一共修了 smoltcp 0.14 的几个问题（详见 `vendor/smoltcp/SUPERNET-PATCH.md`，代码里搜 `superNET patch`）：
   1. **窗口零时整段丢掉**：接收窗口为零时，对方的段被整段丢弃，连同里面的 ACK。我们因此不知道自己发的数据已经送达，双方互等。现在按 RFC 9293 仍然处理 ACK，回复方式不变（挑战 ACK 照常限速）。
   2. **零窗口探测发错了位置**：探测发送的是下一个未发出的字节，而不是第一个未确认的字节，于是对方缺的那段永远补不上。
   3. **窗口重新打开后不重传**：已经发出、但对方没收到的数据，没有任何机制会重传。
   4. **窗口右边界回退**：开启窗口缩放后，通告窗口会被向下取整，右边界最多后退 3 字节，对方已经合法发出的数据会被丢掉。现在接受到曾经通告过的最远边界。
   5. **关闭阶段收不到窗口更新**：调用 `close()` 后还有数据要发时，对方的窗口更新会被当成重复 ACK 丢掉。
   6. **最小重传超时太长**：1000 ms 改为 200 ms，和 Linux 一样。
   7. **快速重传后计时器失效**：快速重传无法重发单独的 FIN，之后重传计时器被置为空闲，连接要等 25 秒的保活才恢复。
- smoltcp 以 `vendor/smoltcp` + `[patch.crates-io]` 的方式引入。打补丁后 smoltcp 自带的 673 项测试全部通过。

### 自动测试（本机 Windows）

- `supernet-wg`：
  - 2 MB 回显、UDP 往返、连接到没有监听的端口被拒绝；
  - **2% 丢包下 1 MiB 回显**（新增，每次跑）：6 次共 18 轮全部完整，每轮 0.3–3.4 秒。修复前有一轮卡了 26 秒。
  - 压力测试 `stress_echo`（`--ignored`）：修复后连续 7 次共 280 轮 4 MiB 回显，只有 1 轮约 3.3 秒，其余都在 0.29–0.43 秒。
- `supernet-core` 12 项：规则、配置、wg 配置与链接、DNS、目标地址解析。
- `supernet-sysproxy` 2 项：只读取系统代理设置，**没有修改本机系统代理**。
- 端到端 1 项：经 HTTP 和 SOCKS5 走节点，4 MiB 回显，走节点的域名不经本地 DNS，直连不进隧道，REJECT，模式和策略组，测速，连接管理。修复后连续 6 次通过，每次约 2.5 秒；修复前 3 次里有 1 次卡满 60 秒。
- smoltcp 自带测试 673 项通过。
- 前端：`tsc --noEmit` 和 `vite build` 通过。

### 真实程序验收（本机 Windows）

- 用 release 版 `dist/windows/superNET.exe` 加临时配置（`local/app-test`，端口 17890，自动连接），连接本地测试节点：
  - 经 HTTP 代理和 SOCKS5 访问 `example.com` 都到达了测试节点；
  - `blocked.test` 返回 403；
  - `baidu.com` 走直连，返回 200；
  - 经 SOCKS5 → WireGuard → 测试节点做 16 MiB 回显：1.3 秒，数据完整（本机回环，双向合计约 200 Mbit/s）。
- 窗口截图：release 版布局正确，显示“已连接”、端口 17890、上传下载速度和模式。
- 浏览器预览（模拟数据）：概览、节点、连接页正常。
- **未验证**：
  - “设为系统代理”开关（不在你电脑上替你改系统设置）；
  - 在界面里手动导入节点、编辑并保存规则；
  - 真实公网节点和真实跨境链路。

### 是否发布

没有发布，也没有提交 git（已 `git init`，没有任何提交）。

### 遗留问题

- 最终还是保留了 256 KiB 的 TCP 缓冲（窗口缩放）。修复后没再出现卡死，但压力测试中仍有约 1/280 轮出现 3 秒停顿，原因还没查清。
- 2% 丢包下吞吐明显下降：smoltcp 只做单段快速重传，不用 SACK 做恢复。真实链路的表现要在 M3 实测。
- SOCKS5 UDP、按进程分流、TUN 模式：M2。
- 规则集只支持本地文件；测速只支持 http://；节点域名只在建立隧道时解析一次；没有托盘。
- 节点服务端安装脚本和 1 核 1G 服务器浸泡测试：M3，需要你提供测试服务器。
