# Zig Linker - 打洞库

基于 Zig 实现的 NAT 穿透 / P2P 打洞库，参考 [linker](../linker) C# 项目实现。

## 功能特性

### 支持的打洞方式

| 方式 | 状态 | 说明 |
|------|------|------|
| UDP 打洞 | ✅ 已实现 | 最基础的 UDP 打洞方式 |
| UDP 同时打开 (UdpP2PNAT) | ✅ 已实现 | UDP Simultaneous Open |
| TCP 同时打开 (TcpP2PNAT) | ✅ 已实现 | TCP Simultaneous Open |
| TCP 低 TTL (TcpNutssb) | ✅ 已实现 | 利用低 TTL 值穿透 NAT |
| UDP 端口映射 | ✅ 已实现 | 需要配置固定端口映射 |
| TCP 端口映射 | ✅ 已实现 | 需要配置固定端口映射 |
| QUIC (MsQuic) | ✅ 已实现 | 纯 Zig 实现的 QUIC 协议栈 |

### 辅助功能

| 功能 | 状态 | 说明 |
|------|------|------|
| UPnP IGD | ✅ 已实现 | 自动端口映射（SSDP + SOAP），支持 IPv4/IPv6 |
| NAT-PMP | ✅ 已实现 | Apple 轻量级端口映射协议 |
| XML 解析器 | ✅ 已实现 | 解析 UPnP SOAP 响应 |
| STUN | ✅ 已实现 | NAT 类型检测，支持 IPv4/IPv6 |
| IPv6 支持 | ✅ 已实现 | 完整的 IPv4/IPv6 双栈支持 |

### IPv6 支持

本库提供完整的 IPv4/IPv6 双栈支持：

**网络工具 (net_utils.zig)**：
- `isIPv4()` / `isIPv6()` - 地址类型检测
- `isIPv6LinkLocal()` - 链路本地地址检测 (fe80::/10)
- `isIPv6GlobalUnicast()` - 全局单播地址检测 (2000::/3)
- `isIPv6UniqueLocal()` - 唯一本地地址检测 (fc00::/7)
- `isIPv4MappedIPv6()` - IPv4 映射地址检测 (::ffff:x.x.x.x)
- `getLocalOutboundAddressV6()` - 获取本机 IPv6 出口地址
- `createDualStackUdpSocket()` / `createDualStackTcpSocket()` - 创建双栈 Socket
- `convertMappedAddress()` / `convertToIPv4MappedIPv6()` - 地址转换

**UPnP IGD (upnp.zig)**：
- IPv6 SSDP 发现支持
  - 链路本地组播: `ff02::c`
  - 站点本地组播: `ff05::c`
- 自动双栈发现（先 IPv4 后 IPv6）
- `PortMapper.initWithIPv6()` - 指定 IPv6 配置

**STUN (stun.zig)**：
- 支持 IPv4 和 IPv6 映射地址解析
- XOR-MAPPED-ADDRESS IPv6 支持 (RFC 5389)

### QUIC 协议实现

本库实现了**完整的 QUIC 协议栈（纯 Zig，无外部依赖）**，功能与 C# linker 的 MsQuic 传输方式对等。

#### QUIC 模块架构

```
src/quic/
├── quic.zig          # 模块入口，导出所有 API
├── types.zig         # QUIC 基础类型定义
├── packet.zig        # QUIC 包编解码
├── frame.zig         # QUIC 帧编解码
├── tls.zig           # TLS 1.3 密钥派生与包保护
├── crypto.zig        # TLS 1.3 握手实现
├── connection.zig    # 连接状态管理
├── recovery.zig      # 丢包检测与拥塞控制
├── client.zig        # QUIC 客户端 API
└── server.zig        # QUIC 服务端 API
```

#### QUIC 功能特性

| 特性 | 状态 | 说明 |
|------|------|------|
| QUIC v1 (RFC 9000) | ✅ | 完整协议实现 |
| TLS 1.3 握手 | ✅ | 内置实现，无需外部 TLS 库 |
| 0-RTT/1-RTT 加密 | ✅ | 多级加密空间 |
| 双向流 (Stream) | ✅ | 支持多流复用 |
| 丢包检测 | ✅ | RFC 9002 算法 |
| 拥塞控制 | ✅ | NewReno + CUBIC |
| 连接迁移 | ✅ | 支持地址变更 |
| NAT 穿透集成 | ✅ | `quic_transport.zig` |

#### 与 C# MsQuic 的对比

| 特性 | C# linker (MsQuic) | Zig linker (纯 Zig) |
|------|-------------------|---------------------|
| 依赖 | 需要系统 MsQuic 库 | 无外部依赖 |
| 平台 | Win10+/Linux/macOS | 跨平台 (Zig 支持的所有平台) |
| TLS 证书 | 必须配置 X509 证书 | 可自生成或配置 |
| 实现方式 | UDP 打洞后本地代理封装 QUIC | 直接 QUIC 协议 |
| 性能 | 依赖 MsQuic 库优化 | 纯 Zig 零分配设计 |

#### QUIC 打洞流程（与 C# 实现对比）

**C# MsQuic 打洞流程**：
1. 双方进行 UDP 打洞（发送认证包、确认包）
2. 打洞成功后，本地启动 UDP 代理 Socket
3. QUIC 连接通过本地代理转发到远端
4. 代理层负责 UDP 数据中转

**Zig QUIC 打洞流程**：
1. 双方进行 QUIC Initial 包打洞
2. 直接在打洞 Socket 上建立 QUIC 连接
3. 完成 TLS 1.3 握手
4. 建立双向流进行数据传输

#### 使用示例

```zig
const quic = @import("quic/quic.zig");

// 客户端
var client = QuicClient.init(allocator, .{
    .server_address = target_addr,
    .alpn = "linker-tunnel",
});
try client.connect();
const stream_id = try client.openStream(true);
try client.send(stream_id, data, false);

// 服务端
var server = QuicServer.init(allocator, .{
    .bind_address = bind_addr,
    .alpn = "linker-tunnel",
});
try server.listen();
const event = try server.accept();
```

## 项目结构

```
src/
├── main.zig              # 主入口
├── root.zig              # 库导出
├── quic/                 # QUIC 协议实现
│   ├── quic.zig          # 模块入口
│   ├── types.zig         # 基础类型（版本、包类型、帧类型等）
│   ├── packet.zig        # 包编解码（Initial/Handshake/1-RTT）
│   ├── frame.zig         # 帧编解码（20+ 种 QUIC 帧）
│   ├── tls.zig           # TLS 密钥派生与包保护
│   ├── crypto.zig        # TLS 1.3 握手流程
│   ├── connection.zig    # 连接状态机
│   ├── recovery.zig      # 丢包检测与拥塞控制
│   ├── client.zig        # 客户端 API
│   └── server.zig        # 服务端 API
└── tunnel/               # 打洞传输层
    ├── types.zig         # 类型定义（NAT 类型、传输类型等）
    ├── log.zig           # 日志系统
    ├── net_utils.zig     # 网络工具（Socket 操作、端口复用、IPv6 支持等）
    ├── stun.zig          # STUN 协议实现（NAT 类型检测，支持 IPv6）
    ├── protocol.zig      # 通信协议定义
    ├── transport.zig     # 7 种打洞传输方式实现
    ├── quic_transport.zig # QUIC 打洞传输集成
    ├── upnp.zig          # UPnP IGD 和 NAT-PMP 自动端口映射（支持 IPv6）
    ├── server.zig        # 打洞信令服务器
    └── client.zig        # 打洞客户端
```

## 编译

```bash
zig build
```

生成的可执行文件位于 `zig-out/bin/`：
- `punch_server.exe` - 打洞信令服务器
- `punch_client.exe` - 打洞客户端
- `zig_linker.exe` - 主程序

## 使用方法

### 启动服务器

```bash
punch_server -p 7891
```

### 客户端连接并等待打洞

```bash
punch_client -s 服务器IP -p 7891 -n "我的电脑"
```

### 列出在线节点

```bash
punch_client -s 服务器IP -l
```

### 发起打洞

```bash
# UDP 打洞（默认）
punch_client -s 服务器IP -t 目标节点ID -m udp

# UDP 同时打开
punch_client -s 服务器IP -t 目标节点ID -m udp-p2p

# TCP 同时打开
punch_client -s 服务器IP -t 目标节点ID -m tcp-p2p

# TCP 低 TTL
punch_client -s 服务器IP -t 目标节点ID -m tcp-ttl

# UDP 端口映射
punch_client -s 服务器IP -t 目标节点ID -m udp-map

# TCP 端口映射
punch_client -s 服务器IP -t 目标节点ID -m tcp-map
```

## NAT 类型支持

支持检测和处理以下 NAT 类型：

- **Open Internet** - 公网 IP，无 NAT
- **Full Cone NAT** - 完全锥形 NAT（最易穿透）
- **Restricted Cone NAT** - 受限锥形 NAT
- **Port Restricted Cone NAT** - 端口受限锥形 NAT
- **Symmetric NAT** - 对称型 NAT（最难穿透）

## 日志输出

打洞过程会输出详细日志，包含：
- 双方 NAT 类型
- 本地/公网 IP 和端口（支持 IPv4/IPv6）
- 打洞尝试过程
- 连接结果和耗时

## 依赖

- Zig 0.15.2+
- 无外部运行时依赖（纯 Zig 实现，链接 libc）
- QUIC 模块无需 MsQuic 或 OpenSSL

## TODO

- [x] ~~实现 MsQuic 传输方式~~ （已完成：纯 Zig QUIC 实现）
- [x] 添加 UPnP/NAT-PMP 自动端口映射
- [x] 支持 IPv6
- [ ] 添加中继服务器（Relay）支持
- [ ] 性能优化和压力测试
- [ ] QUIC 0-RTT 会话恢复
- [ ] QUIC 连接迁移完整测试

## 与 C# linker 实现对比

本项目已实现与 C# linker 打洞模块的功能对等：

| 功能 | C# linker | Zig linker | 说明 |
|------|-----------|------------|------|
| TransportUdp | ✅ | ✅ | 基础 UDP |
| TransportUdpP2PNAT | ✅ | ✅ | UDP 同时打开 |
| TransportTcpP2PNAT | ✅ | ✅ | TCP 同时打开 |
| TransportTcpNutssb | ✅ | ✅ | TCP 低 TTL |
| TransportUdpPortMap | ✅ | ✅ | UDP 端口映射 |
| TransportTcpPortMap | ✅ | ✅ | TCP 端口映射 |
| TransportMsQuic | ✅ (系统库) | ✅ (纯 Zig) | QUIC 打洞 |
| UPnP IGD | ✅ | ✅ | 自动端口映射 |
| NAT-PMP | ✅ | ✅ | Apple 端口映射 |
| STUN | ✅ | ✅ | NAT 类型检测 |

### 实现差异

1. **QUIC 实现**：
   - C# 使用系统 MsQuic 库，需要 Win10+/Linux
   - Zig 使用纯 Zig 实现，无平台限制，无外部依赖

2. **加密方式**：
   - C# MsQuic 需要配置 X509 证书
   - Zig 内置 TLS 1.3，可自动生成临时密钥

3. **打洞流程**：
   - C# 先 UDP 打洞，再通过本地代理封装 QUIC
   - Zig 直接使用 QUIC Initial 包进行打洞

## 许可证

MIT License
