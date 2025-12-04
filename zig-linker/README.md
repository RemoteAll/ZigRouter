# Zig Linker - 打洞库

基于 Zig 实现的 NAT 穿透 / P2P 打洞库，参考 [linker](../linker) C# 项目实现。

## 功能特性

### 支持的打洞方式

| 方式 | 状态 | 说明 |
|------|------|------|
| UDP 打洞 | ✅ 已实现 | 最基础的 UDP 打洞方式 |
| TCP 同时打开 (TcpP2PNAT) | ✅ 已实现 | TCP Simultaneous Open |
| TCP 低 TTL (TcpNutssb) | ✅ 已实现 | 利用低 TTL 值穿透 NAT |
| UDP 端口映射 | ✅ 已实现 | 需要配置固定端口映射 |
| TCP 端口映射 | ✅ 已实现 | 需要配置固定端口映射 |
| MsQuic | ❌ 未实现 | 见下方说明 |

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
    ├── net_utils.zig # 网络工具（Socket 操作、端口复用等）
    ├── stun.zig      # STUN 协议实现（NAT 类型检测）
    ├── protocol.zig  # 通信协议定义
    ├── transport.zig # 6 种打洞传输方式实现
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
- 本地/公网 IP 和端口
- 打洞尝试过程
- 连接结果和耗时

## 依赖

- Zig 0.15.2+
- 无外部运行时依赖（纯 Zig 实现，链接 libc）

## TODO

- [ ] 实现 MsQuic 传输方式
- [x] 添加 UPnP/NAT-PMP 自动端口映射
- [ ] 支持 IPv6
- [ ] 添加中继服务器（Relay）支持
- [ ] 性能优化和压力测试

## 许可证

MIT License
