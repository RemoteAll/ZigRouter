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
| MsQuic | ❌ 未实现 | 见下方说明 |

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

### MsQuic 未实现说明

**MsQuic 传输方式目前仅为占位符，暂未实现。** 原因如下：

1. **外部依赖**：MsQuic 是微软的 QUIC 协议实现，是一个 C 库，需要：
   - 下载或编译 MsQuic 库
   - 在 Zig 中通过 `@cImport` 绑定 C API
   - 链接 MsQuic 动态库/静态库

2. **Zig 生态限制**：Zig 标准库目前没有原生 QUIC 支持

3. **实现复杂度高**：QUIC 协议需要处理：
   - QUIC 握手流程
   - 流 (Stream) 管理
   - 可靠传输与拥塞控制
   - TLS 1.3 加密

**后续实现方案**：
- 方案 A：绑定 MsQuic C 库（完整但复杂）
- 方案 B：使用第三方 Zig QUIC 库（如 zig-quic，但尚不成熟）
- 方案 C：基于 UDP 打洞成功后自行实现简化的可靠传输层

## 项目结构

```
src/
├── main.zig          # 主入口
├── root.zig          # 库导出
└── tunnel/
    ├── types.zig     # 类型定义（NAT 类型、传输类型等）
    ├── log.zig       # 日志系统
    ├── net_utils.zig # 网络工具（Socket 操作、端口复用、IPv6 支持等）
    ├── stun.zig      # STUN 协议实现（NAT 类型检测，支持 IPv6）
    ├── protocol.zig  # 通信协议定义
    ├── transport.zig # 7 种打洞传输方式实现
    ├── upnp.zig      # UPnP IGD 和 NAT-PMP 自动端口映射（支持 IPv6）
    ├── server.zig    # 打洞信令服务器
    └── client.zig    # 打洞客户端
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

## TODO

- [ ] 实现 MsQuic 传输方式
- [x] 添加 UPnP/NAT-PMP 自动端口映射
- [x] 支持 IPv6
- [ ] 添加中继服务器（Relay）支持
- [ ] 性能优化和压力测试

## 许可证

MIT License
