# superNET 使用与构建详解

这里是各平台的详细说明。项目简介和快速开始见 [README](../README.md)。

跨平台的组网 + 代理工具，有两项功能：

- **按规则分流的代理**：命中规则的流量经你自己的服务器（WireGuard 或 Hysteria2 节点）出去，其余流量照常走本机网络。
- **虚拟组网**：你的设备各有一个固定的虚拟地址（10.66.0.x），互相直接访问。能直连就 P2P，连不上时由网内其他设备或服务器中继，全程端到端加密；界面上有实时拓扑图。

平台：Windows、Android、Linux（命令行）、macOS（应用 + 命令行，已在 M4 Mac 上实测代理和组网）、iOS（原生应用 + 隧道扩展，已在 Mac 上编译、模拟器里跑过界面；装到 iPhone 需要付费开发者账号，见 [ios/README.md](../ios/README.md)）。设计见 [docs/DESIGN.md](DESIGN.md)，进度见 [PROGRESS.md](../PROGRESS.md)。

## 目录

| 路径 | 内容 |
|---|---|
| `crates/supernet-wg` | 用户态 WireGuard 隧道：boringtun 负责协议，smoltcp 作为隧道内的 TCP/IP 协议栈 |
| `crates/supernet-core` | 配置、规则引擎、DNS、HTTP/SOCKS5 入站、直连和节点出站、连接统计 |
| `crates/supernet-sysproxy` | 设置并恢复系统代理：Windows（WinINet）、macOS（networksetup）、Linux GNOME（gsettings） |
| `crates/supernet-hy2` | 原生 Hysteria2 客户端（QUIC + TLS 1.3） |
| `crates/supernet-netstack` | TUN 模式的用户态 TCP/IP 协议栈；把 superNET 自己的连接固定到物理网卡 |
| `crates/supernet-tun` | TUN 网卡、路由和 DNS（Windows wintun + WFP 防泄漏、Linux、macOS、Android VpnService） |
| `crates/supernet-mesh` | 虚拟组网：协调协议、P2P 选路和打洞、设备中继 |
| `crates/supernet-coord` | 组网协调服务（跑在你的服务器上，Linux 静态程序） |
| `crates/supernet-cli` | 无界面的 `supernet` 命令（Linux、macOS 上开 TUN 用它） |
| `app/src-tauri/gen/android` | Android 工程（VpnService、VPN 插件） |
| `crates/supernet-testnode` | 本地测试节点（不需要 root 的 WireGuard 服务端），以及端到端测试 |
| `app/` | Tauri 2 + React + Fluent UI 界面 |
| `vendor/smoltcp` | 打过补丁的 smoltcp 0.14（修复隧道内 TCP 卡顿），改动见其中的 `SUPERNET-PATCH.md` |
| `docs/` | 设计文档 |

## 在 Windows 上构建

不需要 Visual Studio：用 windows-gnu 工具链加 llvm-mingw 构建。`scripts/cargo.ps1` 负责设置好环境；llvm-mingw 的位置可以用环境变量 `SUPERNET_MINGW` 指定。

```powershell
scripts/cargo.ps1 test --workspace    # 全部测试
scripts/build-app.ps1                 # 生成 dist\windows\superNET.exe 和 zip
```

## 本地测试节点

```powershell
scripts/cargo.ps1 run -p supernet-testnode -- --listen 127.0.0.1:51820
```

启动后会打印客户端配置和 `supernet://` 链接，在 superNET 的“节点”页粘贴即可。测试节点不能访问互联网，它在自己的隧道地址 10.66.0.1 上提供三个服务：

- echo（端口 7）
- HTTP（端口 80）：`/generate_204` 返回 204，其余路径返回请求的主机名和路径
- DNS（端口 53）：所有域名都解析到 10.66.0.1

因此经节点访问任何 `http://` 网址，看到的都是测试节点的页面。

## 节点服务器（Linux）

```bash
sudo bash node/install.sh                # 内核 WireGuard + NAT，端口默认 51820/udp
sudo supernet-node peer add 电脑         # 输出配置、二维码和 supernet:// 链接
sudo supernet-node peer list             # 每个客户端的最近握手时间和流量
sudo supernet-node status                # 内存、负载、连接跟踪、转发状态
sudo bash node/install.sh --uninstall    # 停用并移除，配置会先备份到 /root
```

- 支持 Debian / Ubuntu，以及 CentOS / Rocky / Alma 8–9（内核没有 WireGuard 时从 ELRepo 装 kmod-wireguard）。
- 防火墙规则放在独立的 nftables 表 `inet supernet` 里，随 wg0 一起创建和删除，不影响原有的 ufw / iptables。
- 云服务商的安全组需要另外放行 UDP 51820 入站。

## 节点类型

出口只使用加密传输：

| 类型 | 导入方式 | 适合 |
|---|---|---|
| WireGuard | wg-quick 配置或 `supernet://` 链接 | 节点内网；UDP 通畅的网络 |
| Hysteria2 | `hysteria2://密码@域名:端口/?sni=…` 分享链接（`hy2://` 也可以） | 跨境、丢包多的线路；兼容 s-ui / sing-box / 官方服务端 |

Hysteria2 的证书校验：
- 有正规证书（比如 Let's Encrypt）时按正常方式校验；
- 自签证书用 `pinSHA256` 固定证书指纹；
- 只带 `insecure=1` 的链接，在应用里导入时会读取当时的证书并自动改为固定指纹；
- `supernet pin-cert host:port [sni]` 可以打印证书指纹；
- 暂不支持 obfs 混淆。

## 无界面运行

```powershell
scripts/cargo.ps1 build -p supernet-cli --release
target/release/supernet --profile profile.yaml --stats 10   # 每 10 秒打印流量和隧道收发字节
```

## TUN 模式（Windows）

- 在概览页打开“TUN 模式”，所有程序的流量（包括 UDP）都按规则分流。需要管理员权限，还需要 superNET.exe 旁边有 wintun.dll（打包脚本会放好）。
- 运行期间，其他网卡上的 DNS 查询会被拦截，防止泄漏。规则在 superNET 退出时自动消失。
- 已知问题：如果其他网卡（比如某些 VPN 软件的虚拟网卡）接口跃点很低、上面的 DNS 又不通，开启后十几秒内系统解析会变慢。停用那块网卡，或者把它的 DNS 改成能用的即可。
- 诊断：用管理员权限运行下面的命令。它会限时开启 TUN，跑一组 DNS、直连和节点探测，结束后自动撤掉网卡和路由。

```powershell
target/debug/supernet tun-test --profile profile.yaml --seconds 60 --log tun-test.log --wintun local/wintun/wintun.dll
```

## 虚拟组网

1. 在服务器上部署协调服务：

   ```powershell
   scripts/build-coord.ps1     # 在 Windows 上交叉编译 Linux 静态程序
   scripts/deploy-coord.ps1    # 装成 systemd 服务 supernet-coord，并打印邀请链接
   ```

   服务器上的 wg0（10.66.0.1）也算网内成员，新设备会自动登记到 wg0。常用命令：
   - `supernet-coord invite --public IP:19190`：显示邀请链接；
   - `supernet-coord members`：列出成员；
   - `supernet-coord remove 10.66.0.x`：移除设备（之后要 `systemctl restart supernet-coord`）。

2. 在每台设备上打开 TUN 模式，到“组网”页粘贴邀请链接（`supernet-net://…`）加入。
3. 设备之间用 10.66.0.x 互相访问。拓扑图显示每对设备当前走哪条路：局域网、IPv6、公网直连、设备中继、服务器中继。

邀请链接相当于网络的密码，不要公开。

## Android

```powershell
scripts/build-android.ps1                                  # 调试版，模拟器用（x86_64）
scripts/build-android.ps1 -Release -Targets x86_64,aarch64 # 正式版，输出到 dist\android
```

- 正式版的签名密钥在 `local/android-release.jks`（不进 git）。请备份它，换了密钥就不能覆盖安装。
- 需要 Android SDK（平台 37.0、platform-tools）、NDK 27 和 JDK 17。
- 第一次连接时，系统会弹出 VPN 授权框；连接期间通知栏显示“superNET 已连接”。

## Linux

### 服务器（没有图形界面）

用命令行版 `supernet`，可以在 Windows 上交叉编译：`scripts/build-linux.ps1` 输出 x86_64 静态程序 `dist/linux/supernet`。

一条命令加入组网并装成开机自启的服务：

```bash
sudo supernet join 'supernet-net://…邀请链接…' --name 我的服务器 --install-service
```

这条命令会：
- 生成设备密钥，写入 `/etc/supernet/profile.yaml`（权限 600）。同一网络再运行一次会沿用原密钥，地址不变。
- 安装 systemd 服务 `supernet`，以“只组网”模式运行（`--mesh-only`）：只有组网网段（10.66.0.0/24）走虚拟网卡，服务器原有的默认路由和 DNS 都不动。
- 默认带网页控制台，只监听 127.0.0.1:9090；不需要时加 `--no-web`。

**网页控制台**和桌面版是同一套界面：节点、规则、组网拓扑、连接、日志都能看能改。打开方法：

```bash
ssh -L 9090:127.0.0.1:9090 用户@服务器
```

然后用浏览器打开服务启动日志里的链接（`journalctl -u supernet`，形如 `http://127.0.0.1:9090/#token=…`）。

- 操作都要带令牌。令牌在 `/etc/supernet/web-token`，只有 root 能读。
- 网页控制台是明文 HTTP，不要直接监听公网，请用 `ssh -L` 访问。

### 手动运行

```bash
sudo supernet --profile profile.yaml                  # 配置里 tun: true 时开 TUN（接管全部流量），有 mesh 段时加入组网
sudo supernet --profile profile.yaml --mesh-only      # 只组网，不改默认路由和 DNS
sudo supernet --profile profile.yaml --web 9090       # 再加网页控制台（127.0.0.1:9090）
```

- TUN 需要 root。路由用 `ip route`，DNS 用 systemd-resolved（`resolvectl`）；退出时都会撤销。
- GNOME 桌面上可以设置系统代理。

### 桌面（图形界面）

在 Debian/Ubuntu 上：

```bash
./scripts/build-linux-app.sh --deps
```

生成 `dist/linux/superNET_<版本>_<架构>.deb`，里面有应用和 `/usr/bin/supernet-cli`。应用本身以普通用户运行（本地代理、GNOME 系统代理）；打开 TUN 时会提示用 sudo 运行 `supernet-cli` 的完整命令。

## macOS

两种构建方式：

- 在 Mac 上：`./scripts/build-macos.sh`，生成 superNET.app、dmg 和命令行版。
- 在 Windows 上交叉编译：`scripts/build-macos-app.ps1`，生成 `dist/macos/superNET-macos-aarch64.tar.gz`（`-Arch x86_64` 生成 Intel 版）。需要先把 Mac 上 MacOSX SDK 的 `usr/include`、`usr/lib` 和各框架的 `.tbd` 存根拷到 `local/toolchain/MacOSX.sdk`（约 50 MB）。解压后在 Mac 上运行 `codesign --force --deep -s - superNET.app`。

用法：

- 应用本身用系统代理模式（networksetup）。
- TUN 和组网需要 root：应用包里带了命令行版 `superNET.app/Contents/MacOS/supernet-cli`。在应用里打开 TUN 时，会显示完整命令，例如：

  ```bash
  sudo /Applications/superNET.app/Contents/MacOS/supernet-cli --profile ~/Library/Application\ Support/app.supernet.client/profile.yaml --tun
  ```

  网卡是 utun，路由用 `route`，DNS 用 scutil 的动态配置（不落盘）；退出时都撤销。用 sudo 运行时在数据目录里新建的文件会交还给原用户，之后应用照常能写。
- 如果 Shadowrocket、ClashX 等别的 VPN 占着默认路由，TUN 会拒绝启动，请先断开它们。
- 没有付费账号无法公证，第一次打开时请右键选“打开”。

## 规则示例

```
DOMAIN-SUFFIX,github.com,代理
IP-CIDR,10.66.0.0/24,代理,no-resolve
GEOIP,LAN,DIRECT
MATCH,DIRECT
```
