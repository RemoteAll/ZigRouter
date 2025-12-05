//! 打洞传输模块
//! 实现 6 种打洞方式：UDP、TcpP2PNAT、TcpNutssb、UdpPortMap、TcpPortMap、MsQuic
//! 参考 C# linker 项目的实现

const std = @import("std");
const net = std.net;
const posix = std.posix;
const types = @import("types.zig");
const log = @import("log.zig");
const net_utils = @import("net_utils.zig");
const protocol = @import("protocol.zig");

/// 全局字符串标识
const GLOBAL_STRING = "linker.zig";

/// UDP 认证字节
const UDP_AUTH_BYTES = GLOBAL_STRING ++ ".udp.ttl1";

/// UDP 结束字节
const UDP_END_BYTES = GLOBAL_STRING ++ ".udp.end1";

/// TCP 认证字节
const TCP_AUTH_BYTES = GLOBAL_STRING ++ ".tcp.ttl1";

/// TCP 结束字节
const TCP_END_BYTES = GLOBAL_STRING ++ ".tcp.end1";

/// Hello 握手消息 (打洞成功后双方互发验证)
pub const HELLO_REQUEST = GLOBAL_STRING ++ ".hello.req";
pub const HELLO_RESPONSE = GLOBAL_STRING ++ ".hello.ack";

/// 传输错误
pub const TransportError = error{
    /// 连接失败
    ConnectionFailed,
    /// 超时
    Timeout,
    /// 被拒绝
    Rejected,
    /// 网络错误
    NetworkError,
    /// 协议错误
    ProtocolError,
    /// 端口映射未配置
    PortMapNotConfigured,
    /// SSL 证书未找到
    CertificateNotFound,
    /// 不支持
    Unsupported,
    /// 内存不足
    OutOfMemory,
};

/// 隧道连接接口
pub const ITunnelConnection = struct {
    /// 连接信息
    info: types.TunnelConnectionInfo,
    /// 底层 socket
    socket: posix.socket_t,
    /// 是否已连接
    connected: bool = true,
    /// 发送缓冲区大小
    buffer_size: usize = 8 * 1024,

    /// 发送数据
    pub fn send(self: *ITunnelConnection, data: []const u8) !usize {
        if (!self.connected) return error.NotConnected;
        return posix.send(self.socket, data, 0) catch |e| {
            self.connected = false;
            return e;
        };
    }

    /// 接收数据
    pub fn recv(self: *ITunnelConnection, buf: []u8) !usize {
        if (!self.connected) return error.NotConnected;
        return posix.recv(self.socket, buf, 0) catch |e| {
            if (e == error.WouldBlock) return 0;
            self.connected = false;
            return e;
        };
    }

    /// 发送到指定地址 (UDP)
    pub fn sendTo(self: *ITunnelConnection, data: []const u8, addr: net.Address) !usize {
        if (!self.connected) return error.NotConnected;
        return posix.sendto(self.socket, data, 0, &addr.any, addr.getOsSockLen()) catch |e| {
            return e;
        };
    }

    /// 从指定地址接收 (UDP)
    pub fn recvFrom(self: *ITunnelConnection, buf: []u8, addr: *net.Address) !usize {
        if (!self.connected) return error.NotConnected;
        var from_addr: posix.sockaddr = undefined;
        var from_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        const len = posix.recvfrom(self.socket, buf, 0, &from_addr, &from_len) catch |e| {
            if (e == error.WouldBlock) return 0;
            return e;
        };
        addr.* = .{ .any = from_addr };
        return len;
    }

    /// 关闭连接
    pub fn close(self: *ITunnelConnection) void {
        if (self.connected) {
            posix.close(self.socket);
            self.connected = false;
        }
    }

    /// Hello 握手验证 - 确认打洞连接真正可用
    /// 正向方先发送 Hello 请求，反向方收到后回复，双方都验证成功才算真正打通
    /// @param is_initiator 是否是打洞发起方（正向方）
    /// @param timeout_ms 超时时间（毫秒）
    /// @return 握手是否成功
    pub fn performHelloHandshake(self: *ITunnelConnection, is_initiator: bool, timeout_ms: u32) !bool {
        if (!self.connected) return error.NotConnected;

        var recv_buf: [128]u8 = undefined;
        const protocol_type = self.info.protocol_type;

        // 设置接收超时
        net_utils.setRecvTimeout(self.socket, timeout_ms) catch {};

        if (is_initiator) {
            // 发起方：先发送 Hello 请求，等待响应
            log.debug("Hello 握手: 发起方发送请求...", .{});

            if (protocol_type == .udp) {
                _ = posix.sendto(self.socket, HELLO_REQUEST, 0, &self.info.remote_endpoint.any, self.info.remote_endpoint.getOsSockLen()) catch |e| {
                    log.err("Hello 握手: 发送请求失败: {any}", .{e});
                    return false;
                };
            } else {
                _ = posix.send(self.socket, HELLO_REQUEST, 0) catch |e| {
                    log.err("Hello 握手: 发送请求失败: {any}", .{e});
                    return false;
                };
            }

            // 等待响应
            const recv_len = if (protocol_type == .udp) blk: {
                var from_addr: posix.sockaddr = undefined;
                var from_len: posix.socklen_t = @sizeOf(posix.sockaddr);
                break :blk posix.recvfrom(self.socket, &recv_buf, 0, &from_addr, &from_len) catch |e| {
                    log.err("Hello 握手: 等待响应超时: {any}", .{e});
                    return false;
                };
            } else blk: {
                break :blk posix.recv(self.socket, &recv_buf, 0) catch |e| {
                    log.err("Hello 握手: 等待响应超时: {any}", .{e});
                    return false;
                };
            };

            // 验证响应
            if (recv_len >= HELLO_RESPONSE.len and std.mem.eql(u8, recv_buf[0..HELLO_RESPONSE.len], HELLO_RESPONSE)) {
                log.info("Hello 握手: 收到对方响应，连接验证成功! ✓", .{});
                return true;
            } else {
                log.warn("Hello 握手: 响应内容不匹配", .{});
                return false;
            }
        } else {
            // 响应方：先等待 Hello 请求，收到后回复
            log.debug("Hello 握手: 响应方等待请求...", .{});

            const recv_len = if (protocol_type == .udp) blk: {
                var from_addr: posix.sockaddr = undefined;
                var from_len: posix.socklen_t = @sizeOf(posix.sockaddr);
                break :blk posix.recvfrom(self.socket, &recv_buf, 0, &from_addr, &from_len) catch |e| {
                    log.err("Hello 握手: 等待请求超时: {any}", .{e});
                    return false;
                };
            } else blk: {
                break :blk posix.recv(self.socket, &recv_buf, 0) catch |e| {
                    log.err("Hello 握手: 等待请求超时: {any}", .{e});
                    return false;
                };
            };

            // 验证请求
            if (recv_len >= HELLO_REQUEST.len and std.mem.eql(u8, recv_buf[0..HELLO_REQUEST.len], HELLO_REQUEST)) {
                log.debug("Hello 握手: 收到对方请求，发送响应...", .{});

                // 发送响应
                if (protocol_type == .udp) {
                    _ = posix.sendto(self.socket, HELLO_RESPONSE, 0, &self.info.remote_endpoint.any, self.info.remote_endpoint.getOsSockLen()) catch |e| {
                        log.err("Hello 握手: 发送响应失败: {any}", .{e});
                        return false;
                    };
                } else {
                    _ = posix.send(self.socket, HELLO_RESPONSE, 0) catch |e| {
                        log.err("Hello 握手: 发送响应失败: {any}", .{e});
                        return false;
                    };
                }

                log.info("Hello 握手: 已发送响应，连接验证成功! ✓", .{});
                return true;
            } else {
                log.warn("Hello 握手: 请求内容不匹配", .{});
                return false;
            }
        }
    }
};

/// 传输回调接口
pub const TransportCallbacks = struct {
    /// 收到连接时的回调
    on_connected: ?*const fn (*ITunnelConnection) void = null,
    /// 连接失败时的回调
    on_failed: ?*const fn (types.TransportType, []const u8) void = null,
    /// 用户数据
    user_data: ?*anyopaque = null,
};

/// ============================================================
/// UDP 打洞传输
/// 大致原理（正向打洞）：
/// A 通知 B，我要连你
/// B 收到通知，开始监听收取消息，并且给A随便发送个消息（低TTL），这时候A肯定收不到
/// A 监听收取消息，并且给 B 发送试探消息，如果B能收到消息，就会回复一条消息
/// A 能收到回复，就说明通了，这隧道能用
/// ============================================================
pub const TransportUdp = struct {
    const Self = @This();

    /// 传输方式名称
    pub const NAME = "Udp";
    /// 传输方式标签
    pub const LABEL = "UDP、非常纯";
    /// 协议类型
    pub const PROTOCOL_TYPE = types.TunnelProtocolType.udp;
    /// 默认排序
    pub const ORDER: u8 = 3;

    /// 配置
    config: Config,
    /// 回调
    callbacks: TransportCallbacks,

    pub const Config = struct {
        /// 连接超时 (毫秒)
        connect_timeout_ms: u32 = 5000,
        /// 认证超时 (毫秒)
        auth_timeout_ms: u32 = 500,
        /// 重试次数
        retry_count: u32 = 3,
        /// 是否启用 SSL
        ssl: bool = false,
    };

    pub fn init(cfg: Config, callbacks: TransportCallbacks) Self {
        return Self{
            .config = cfg,
            .callbacks = callbacks,
        };
    }

    /// 主动连接对方 (正向打洞)
    pub fn connectAsync(self: *Self, info: *const types.TunnelTransportInfo) !?ITunnelConnection {
        log.logPunchStart(.udp, info.direction, info.local, info.remote);

        if (info.direction == .forward) {
            // 正向连接
            return try self.connectForward(info);
        } else {
            // 反向连接：先绑定监听，发送 TTL 包，等待对方连接
            return try self.connectReverse(info);
        }
    }

    /// 正向连接实现
    fn connectForward(self: *Self, info: *const types.TunnelTransportInfo) !?ITunnelConnection {
        log.debug("UDP 正向连接开始", .{});

        // 创建 UDP socket
        const sock = try net_utils.createReuseUdpSocket(info.local.local);
        errdefer posix.close(sock);

        // 设置接收超时
        try net_utils.setRecvTimeout(sock, self.config.auth_timeout_ms);

        // 向对方发送认证消息
        for (info.remote_endpoints) |ep| {
            log.logConnectAttempt(ep, 1);
            _ = posix.sendto(sock, UDP_AUTH_BYTES, 0, &ep.any, ep.getOsSockLen()) catch continue;
            std.Thread.sleep(50 * std.time.ns_per_ms);
        }

        // 等待对方回复
        var recv_buf: [1024]u8 = undefined;
        var from_addr: posix.sockaddr = undefined;
        var from_len: posix.socklen_t = @sizeOf(posix.sockaddr);

        const recv_len = posix.recvfrom(sock, &recv_buf, 0, &from_addr, &from_len) catch |e| {
            log.err("UDP 正向连接失败: 接收超时或错误: {any}", .{e});
            log.logPunchFailed(.udp, "接收响应超时");
            return null;
        };

        if (recv_len == 0) {
            log.logPunchFailed(.udp, "收到空响应");
            return null;
        }

        // 发送结束确认
        _ = posix.sendto(sock, UDP_END_BYTES, 0, &from_addr, from_len) catch {};

        const remote_ep = net.Address{ .any = from_addr };
        const remote_ep_converted = net_utils.convertMappedAddress(remote_ep);

        log.info("UDP 打洞成功! 远程端点: {any}", .{remote_ep_converted});

        const connection = ITunnelConnection{
            .info = types.TunnelConnectionInfo{
                .remote_endpoint = remote_ep_converted,
                .remote_machine_id = info.remote.machine_id,
                .remote_machine_name = info.remote.machine_name,
                .transport_name = .udp,
                .direction = info.direction,
                .protocol_type = .udp,
                .tunnel_type = .p2p,
                .mode = .client,
                .ssl = info.ssl,
                .connected_at = std.time.timestamp(),
            },
            .socket = sock,
            .connected = true,
        };

        log.logPunchSuccess(.udp, connection.info);
        return connection;
    }

    /// 反向连接实现
    fn connectReverse(self: *Self, info: *const types.TunnelTransportInfo) !?ITunnelConnection {
        log.debug("UDP 反向连接开始", .{});

        // 创建 UDP socket 并监听
        const sock = try net_utils.createReuseUdpSocket(info.local.local);
        errdefer posix.close(sock);

        // 发送 TTL 包 (低 TTL，用于打开 NAT 映射)
        self.sendTtlPackets(info, sock);

        // 设置接收超时
        try net_utils.setRecvTimeout(sock, self.config.connect_timeout_ms);

        // 等待对方消息
        var recv_buf: [1024]u8 = undefined;
        var from_addr: posix.sockaddr = undefined;
        var from_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        var got_auth = false; // 是否收到过认证消息

        while (true) {
            const recv_len = posix.recvfrom(sock, &recv_buf, 0, &from_addr, &from_len) catch |e| {
                if (e == error.WouldBlock) {
                    log.logPunchFailed(.udp, "等待连接超时");
                    return null;
                }
                return e;
            };

            if (recv_len == 0) continue;

            const data = recv_buf[0..recv_len];
            const remote_ep = net.Address{ .any = from_addr };

            // 检查是否是结束消息
            if (std.mem.eql(u8, data, UDP_END_BYTES)) {
                const remote_ep_converted = net_utils.convertMappedAddress(remote_ep);

                log.info("UDP 反向打洞成功! 远程端点: {any}", .{remote_ep_converted});

                const connection = ITunnelConnection{
                    .info = types.TunnelConnectionInfo{
                        .remote_endpoint = remote_ep_converted,
                        .remote_machine_id = info.remote.machine_id,
                        .remote_machine_name = info.remote.machine_name,
                        .transport_name = .udp,
                        .direction = info.direction,
                        .protocol_type = .udp,
                        .tunnel_type = .p2p,
                        .mode = .server,
                        .ssl = info.ssl,
                        .connected_at = std.time.timestamp(),
                    },
                    .socket = sock,
                    .connected = true,
                };

                log.logPunchSuccess(.udp, connection.info);
                return connection;
            } else if (recv_len >= HELLO_REQUEST.len and std.mem.eql(u8, data[0..HELLO_REQUEST.len], HELLO_REQUEST)) {
                // 收到 Hello 请求，说明对方已经打洞成功并开始握手
                // 直接回复 Hello 响应，并返回连接成功
                log.info("UDP 反向: 收到对方 Hello 请求，对方已打洞成功!", .{});
                _ = posix.sendto(sock, HELLO_RESPONSE, 0, &from_addr, from_len) catch {};

                const remote_ep_converted = net_utils.convertMappedAddress(remote_ep);
                const connection = ITunnelConnection{
                    .info = types.TunnelConnectionInfo{
                        .remote_endpoint = remote_ep_converted,
                        .remote_machine_id = info.remote.machine_id,
                        .remote_machine_name = info.remote.machine_name,
                        .transport_name = .udp,
                        .direction = info.direction,
                        .protocol_type = .udp,
                        .tunnel_type = .p2p,
                        .mode = .server,
                        .ssl = info.ssl,
                        .connected_at = std.time.timestamp(),
                        .hello_completed = true, // 标记 Hello 已完成
                    },
                    .socket = sock,
                    .connected = true,
                };

                log.logPunchSuccess(.udp, connection.info);
                return connection;
            } else if (std.mem.eql(u8, data, UDP_AUTH_BYTES)) {
                // 收到认证消息，回显
                got_auth = true;
                _ = posix.sendto(sock, data, 0, &from_addr, from_len) catch {};
            } else if (got_auth) {
                // 已经收到过认证，可能是其他消息，回显
                _ = posix.sendto(sock, data, 0, &from_addr, from_len) catch {};
            }
        }
    }

    /// 发送 TTL 包
    fn sendTtlPackets(self: *Self, info: *const types.TunnelTransportInfo, sock: posix.socket_t) void {
        _ = self;
        for (info.remote_endpoints) |ep| {
            // 创建临时 socket 发送低 TTL 包
            const ttl_sock = posix.socket(
                ep.any.family,
                posix.SOCK.DGRAM,
                posix.IPPROTO.UDP,
            ) catch continue;
            defer posix.close(ttl_sock);

            net_utils.setReuseAddr(ttl_sock, true) catch {};
            posix.bind(ttl_sock, &info.local.local.any, info.local.local.getOsSockLen()) catch {};

            // 设置 TTL
            const ttl: u8 = @intCast(@min(info.local.route_level, 3));
            net_utils.setTtl(ttl_sock, ttl) catch {};

            log.logSendTtl(ep, ttl);
            _ = posix.sendto(ttl_sock, UDP_AUTH_BYTES, 0, &ep.any, ep.getOsSockLen()) catch {};
        }

        // 使用正常 socket 也发送一份
        for (info.remote_endpoints) |ep| {
            _ = posix.sendto(sock, UDP_AUTH_BYTES, 0, &ep.any, ep.getOsSockLen()) catch {};
        }
    }

    /// 收到打洞开始通知时的处理
    pub fn onBegin(self: *Self, info: *const types.TunnelTransportInfo) !?ITunnelConnection {
        if (info.direction == .forward) {
            // 对方要连我，我监听等待
            return try self.connectReverse(info);
        } else {
            // 我要去连对方
            return try self.connectForward(info);
        }
    }
};

/// ============================================================
/// UDP 同时打开 (UDP Simultaneous Open) 打洞传输
/// 大致原理：
/// A 通知 B，B 立马发送 UDP 给 A，A 也同时发送 UDP 给 B
/// 双方同时发送，利用 NAT 的特性使数据包能够穿透
/// 比普通 UDP 打洞更简单直接，双方都主动发送
/// ============================================================
pub const TransportUdpP2PNAT = struct {
    const Self = @This();

    pub const NAME = "UdpP2PNAT";
    pub const LABEL = "UDP、同时打开";
    pub const PROTOCOL_TYPE = types.TunnelProtocolType.udp;
    pub const ORDER: u8 = 3;

    config: Config,
    callbacks: TransportCallbacks,

    pub const Config = struct {
        /// 连接超时 (毫秒)
        connect_timeout_ms: u32 = 500,
        /// 重试次数
        retry_count: u32 = 5,
        /// 是否启用 SSL
        ssl: bool = false,
    };

    pub fn init(cfg: Config, callbacks: TransportCallbacks) Self {
        return Self{
            .config = cfg,
            .callbacks = callbacks,
        };
    }

    /// 连接对方 - 双方同时发起连接
    pub fn connectAsync(self: *Self, info: *const types.TunnelTransportInfo) !?ITunnelConnection {
        log.logPunchStart(.udp_p2p_nat, info.direction, info.local, info.remote);

        // UDP 同时打开模式：无论正向反向，双方都执行相同的连接逻辑
        const mode: types.TunnelMode = if (info.direction == .forward) .client else .server;
        return try self.connectForward(info, mode);
    }

    /// 收到打洞开始通知时的处理 - 立即开始双向发送
    pub fn onBegin(self: *Self, info: *const types.TunnelTransportInfo) !?ITunnelConnection {
        // 收到对方通知后，立即开始连接
        const mode: types.TunnelMode = if (info.direction == .forward) .server else .client;
        return try self.connectForward(info, mode);
    }

    /// 执行同时打开连接
    /// 双方同时向对方发送 UDP 包，利用 NAT 的映射特性完成穿透
    fn connectForward(self: *Self, info: *const types.TunnelTransportInfo, mode: types.TunnelMode) !?ITunnelConnection {
        log.debug("UDP P2PNAT 连接开始, 模式: {s}", .{mode.toString()});

        if (info.remote_endpoints.len == 0) {
            log.logPunchFailed(.udp_p2p_nat, "没有可用的远程端点");
            return null;
        }

        // 创建 UDP socket 并绑定到本地端口
        const sock = try net_utils.createReuseUdpSocket(info.local.local);
        errdefer posix.close(sock);

        // 设置接收超时
        try net_utils.setRecvTimeout(sock, self.config.connect_timeout_ms);

        // 等待 500ms 让双方都准备好
        std.Thread.sleep(500 * std.time.ns_per_ms);

        var recv_buf: [1024]u8 = undefined;
        var from_addr: posix.sockaddr = undefined;
        var from_len: posix.socklen_t = @sizeOf(posix.sockaddr);

        // 重试多次
        var retry: u32 = 0;
        while (retry < self.config.retry_count) : (retry += 1) {
            log.debug("UDP P2PNAT 尝试 {d}/{d}", .{ retry + 1, self.config.retry_count });

            // 向所有远程端点发送认证消息
            for (info.remote_endpoints) |ep| {
                log.logConnectAttempt(ep, retry + 1);
                _ = posix.sendto(sock, UDP_AUTH_BYTES, 0, &ep.any, ep.getOsSockLen()) catch |e| {
                    log.debug("发送到 {any} 失败: {any}", .{ ep, e });
                    continue;
                };
            }

            // 尝试接收对方的响应
            const recv_result = posix.recvfrom(sock, &recv_buf, 0, &from_addr, &from_len);

            if (recv_result) |recv_len| {
                if (recv_len > 0) {
                    const remote_ep = net.Address{ .any = from_addr };

                    log.debug("收到来自 {any} 的响应, 长度: {d}", .{ remote_ep, recv_len });

                    // 收到响应后，再发送一个确认包
                    _ = posix.sendto(sock, UDP_AUTH_BYTES, 0, &from_addr, from_len) catch {};

                    // 清空可能的后续包
                    while (true) {
                        net_utils.setRecvTimeout(sock, 100) catch break;
                        _ = posix.recvfrom(sock, &recv_buf, 0, &from_addr, &from_len) catch break;
                    }

                    // 恢复正常超时
                    net_utils.setRecvTimeout(sock, self.config.connect_timeout_ms) catch {};

                    const remote_ep_converted = net_utils.convertMappedAddress(remote_ep);

                    log.info("UDP P2PNAT 打洞成功! 远程端点: {any}", .{remote_ep_converted});

                    const connection = ITunnelConnection{
                        .info = types.TunnelConnectionInfo{
                            .remote_endpoint = remote_ep_converted,
                            .remote_machine_id = info.remote.machine_id,
                            .remote_machine_name = info.remote.machine_name,
                            .transport_name = .udp_p2p_nat,
                            .direction = info.direction,
                            .protocol_type = .udp,
                            .tunnel_type = .p2p,
                            .mode = mode,
                            .ssl = info.ssl,
                            .connected_at = std.time.timestamp(),
                        },
                        .socket = sock,
                        .connected = true,
                    };

                    log.logPunchSuccess(.udp_p2p_nat, connection.info);
                    return connection;
                }
            } else |e| {
                if (e != error.WouldBlock) {
                    log.debug("接收失败: {any}", .{e});
                }
            }
        }

        log.logPunchFailed(.udp_p2p_nat, "所有连接尝试均失败");
        posix.close(sock);
        return null;
    }
};

/// ============================================================
/// TCP 同时打开 (TCP Simultaneous Open) 打洞传输
/// 大致原理：
/// A 通知 B，B 立马连接 A，A 也同时去连接 B
/// 利用 TCP 的同时打开特性
/// ============================================================
pub const TransportTcpP2PNAT = struct {
    const Self = @This();

    pub const NAME = "TcpP2PNAT";
    pub const LABEL = "TCP、同时打开";
    pub const PROTOCOL_TYPE = types.TunnelProtocolType.tcp;
    pub const ORDER: u8 = 4;

    config: Config,
    callbacks: TransportCallbacks,

    pub const Config = struct {
        connect_timeout_ms: u32 = 500,
        retry_count: u32 = 5,
        ssl: bool = false,
    };

    pub fn init(cfg: Config, callbacks: TransportCallbacks) Self {
        return Self{
            .config = cfg,
            .callbacks = callbacks,
        };
    }

    /// 连接
    pub fn connectAsync(self: *Self, info: *const types.TunnelTransportInfo) !?ITunnelConnection {
        log.logPunchStart(.tcp_p2p_nat, info.direction, info.local, info.remote);

        const mode: types.TunnelMode = if (info.direction == .forward) .client else .server;
        return try self.connectForward(info, mode);
    }

    fn connectForward(self: *Self, info: *const types.TunnelTransportInfo, mode: types.TunnelMode) !?ITunnelConnection {
        log.debug("TCP P2PNAT 连接开始, 模式: {s}", .{mode.toString()});

        var retry: u32 = 0;
        while (retry < self.config.retry_count) : (retry += 1) {
            // 尝试连接所有端点
            for (info.remote_endpoints) |ep| {
                if (try self.tryConnect(info, ep, mode)) |conn| {
                    return conn;
                }
            }
        }

        log.logPunchFailed(.tcp_p2p_nat, "所有连接尝试均失败");
        return null;
    }

    fn tryConnect(self: *Self, info: *const types.TunnelTransportInfo, ep: net.Address, mode: types.TunnelMode) !?ITunnelConnection {
        _ = self;
        log.logConnectAttempt(ep, 1);

        // 创建 TCP socket
        const sock = try net_utils.createReuseTcpSocket(info.local.local);
        errdefer posix.close(sock);

        // 设置 Keep-Alive
        net_utils.setKeepAlive(sock, true) catch {};

        // 尝试连接
        posix.connect(sock, &ep.any, ep.getOsSockLen()) catch |e| {
            log.debug("TCP 连接失败: {any}", .{e});
            return null;
        };

        // 连接成功，进行认证
        if (mode == .client) {
            // 客户端：发送认证
            _ = posix.send(sock, TCP_AUTH_BYTES, 0) catch return null;

            // 等待响应
            var buf: [64]u8 = undefined;
            const recv_len = posix.recv(sock, &buf, 0) catch return null;
            if (recv_len == 0) return null;
        } else {
            // 服务端：等待认证
            var buf: [64]u8 = undefined;
            const recv_len = posix.recv(sock, &buf, 0) catch return null;
            if (recv_len == 0) return null;

            // 发送响应
            _ = posix.send(sock, TCP_END_BYTES, 0) catch return null;
        }

        const remote_ep_converted = net_utils.convertMappedAddress(ep);

        log.info("TCP P2PNAT 打洞成功! 远程端点: {any}", .{remote_ep_converted});

        const connection = ITunnelConnection{
            .info = types.TunnelConnectionInfo{
                .remote_endpoint = remote_ep_converted,
                .remote_machine_id = info.remote.machine_id,
                .remote_machine_name = info.remote.machine_name,
                .transport_name = .tcp_p2p_nat,
                .direction = info.direction,
                .protocol_type = .tcp,
                .tunnel_type = .p2p,
                .mode = mode,
                .ssl = info.ssl,
                .connected_at = std.time.timestamp(),
            },
            .socket = sock,
            .connected = true,
        };

        log.logPunchSuccess(.tcp_p2p_nat, connection.info);
        return connection;
    }

    pub fn onBegin(self: *Self, info: *const types.TunnelTransportInfo) !?ITunnelConnection {
        const mode: types.TunnelMode = if (info.direction == .forward) .server else .client;
        return try self.connectForward(info, mode);
    }
};

/// ============================================================
/// TCP 低 TTL 打洞传输
/// 大致原理（正向打洞）：
/// A 通知 B，我要连你
/// B 收到通知，开始监听连接，并且以低 TTL 方式尝试连接 A，这时候 A 肯定收不到
/// A 正常去连接 B，能连接成功则通道可用
/// ============================================================
pub const TransportTcpNutssb = struct {
    const Self = @This();

    pub const NAME = "TcpNutssb";
    pub const LABEL = "TCP、低TTL";
    pub const PROTOCOL_TYPE = types.TunnelProtocolType.tcp;
    pub const ORDER: u8 = 5;

    config: Config,
    callbacks: TransportCallbacks,

    pub const Config = struct {
        connect_timeout_ms: u32 = 500,
        listen_timeout_ms: u32 = 30000,
        ssl: bool = false,
    };

    pub fn init(cfg: Config, callbacks: TransportCallbacks) Self {
        return Self{
            .config = cfg,
            .callbacks = callbacks,
        };
    }

    pub fn connectAsync(self: *Self, info: *const types.TunnelTransportInfo) !?ITunnelConnection {
        log.logPunchStart(.tcp_nutssb, info.direction, info.local, info.remote);

        if (info.direction == .forward) {
            // 正向连接
            return try self.connectForward(info);
        } else {
            // 反向连接
            return try self.connectReverse(info);
        }
    }

    fn connectForward(_: *Self, info: *const types.TunnelTransportInfo) !?ITunnelConnection {
        log.debug("TCP Nutssb 正向连接开始", .{});

        for (info.remote_endpoints) |ep| {
            log.logConnectAttempt(ep, 1);

            // 创建 TCP socket
            const sock = try net_utils.createReuseTcpSocket(info.local.local);
            errdefer posix.close(sock);

            net_utils.setKeepAlive(sock, true) catch {};

            // 尝试连接
            posix.connect(sock, &ep.any, ep.getOsSockLen()) catch {
                posix.close(sock);
                continue;
            };

            const remote_ep_converted = net_utils.convertMappedAddress(ep);

            log.info("TCP Nutssb 连接成功! 远程端点: {any}", .{remote_ep_converted});

            const connection = ITunnelConnection{
                .info = types.TunnelConnectionInfo{
                    .remote_endpoint = remote_ep_converted,
                    .remote_machine_id = info.remote.machine_id,
                    .remote_machine_name = info.remote.machine_name,
                    .transport_name = .tcp_nutssb,
                    .direction = info.direction,
                    .protocol_type = .tcp,
                    .tunnel_type = .p2p,
                    .mode = .client,
                    .ssl = info.ssl,
                    .connected_at = std.time.timestamp(),
                },
                .socket = sock,
                .connected = true,
            };

            log.logPunchSuccess(.tcp_nutssb, connection.info);
            return connection;
        }

        log.logPunchFailed(.tcp_nutssb, "所有端点连接失败");
        return null;
    }

    fn connectReverse(self: *Self, info: *const types.TunnelTransportInfo) !?ITunnelConnection {
        log.debug("TCP Nutssb 反向连接开始 (监听)", .{});

        // 创建监听 socket
        const listen_sock = try net_utils.createReuseTcpSocket(info.local.local);
        defer posix.close(listen_sock);

        posix.listen(listen_sock, 128) catch |e| {
            log.err("TCP 监听失败: {any}", .{e});
            return null;
        };

        // 发送低 TTL 包
        self.sendTtlPackets(info);

        // 设置接收超时
        net_utils.setRecvTimeout(listen_sock, self.config.listen_timeout_ms) catch {};

        // 等待连接
        var client_addr: posix.sockaddr = undefined;
        var client_len: posix.socklen_t = @sizeOf(posix.sockaddr);

        const client_sock = posix.accept(listen_sock, &client_addr, &client_len, 0) catch |e| {
            log.err("TCP accept 失败: {any}", .{e});
            log.logPunchFailed(.tcp_nutssb, "等待连接超时");
            return null;
        };

        const remote_ep = net.Address{ .any = client_addr };
        const remote_ep_converted = net_utils.convertMappedAddress(remote_ep);

        log.info("TCP Nutssb 收到连接! 远程端点: {any}", .{remote_ep_converted});

        const connection = ITunnelConnection{
            .info = types.TunnelConnectionInfo{
                .remote_endpoint = remote_ep_converted,
                .remote_machine_id = info.remote.machine_id,
                .remote_machine_name = info.remote.machine_name,
                .transport_name = .tcp_nutssb,
                .direction = info.direction,
                .protocol_type = .tcp,
                .tunnel_type = .p2p,
                .mode = .server,
                .ssl = info.ssl,
                .connected_at = std.time.timestamp(),
            },
            .socket = client_sock,
            .connected = true,
        };

        log.logPunchSuccess(.tcp_nutssb, connection.info);
        return connection;
    }

    fn sendTtlPackets(self: *Self, info: *const types.TunnelTransportInfo) void {
        _ = self;
        for (info.remote_endpoints) |ep| {
            // 创建临时 socket 发送低 TTL 包
            const ttl_sock = posix.socket(ep.any.family, posix.SOCK.STREAM, posix.IPPROTO.TCP) catch continue;

            net_utils.setReuseAddr(ttl_sock, true) catch {};
            posix.bind(ttl_sock, &info.local.local.any, info.local.local.getOsSockLen()) catch {
                posix.close(ttl_sock);
                continue;
            };

            // 设置低 TTL
            const ttl: u8 = @intCast(@min(info.local.route_level, 2));
            net_utils.setTtl(ttl_sock, ttl) catch {};

            log.logSendTtl(ep, ttl);

            // 非阻塞连接 (会失败，但这就是我们想要的)
            _ = posix.connect(ttl_sock, &ep.any, ep.getOsSockLen()) catch {};
            posix.close(ttl_sock);
        }
    }

    pub fn onBegin(self: *Self, info: *const types.TunnelTransportInfo) !?ITunnelConnection {
        if (info.direction == .forward) {
            // 对方要连我
            return try self.connectReverse(info);
        } else {
            // 我要去连对方
            return try self.connectForward(info);
        }
    }
};

/// ============================================================
/// UDP 端口映射传输
/// 基于端口映射的打洞，需要配置固定端口
/// ============================================================
pub const TransportUdpPortMap = struct {
    const Self = @This();

    pub const NAME = "UdpPortMap";
    pub const LABEL = "UDP、端口映射";
    pub const PROTOCOL_TYPE = types.TunnelProtocolType.udp;
    pub const ORDER: u8 = 1;

    config: Config,
    callbacks: TransportCallbacks,
    listen_socket: ?posix.socket_t = null,

    pub const Config = struct {
        connect_timeout_ms: u32 = 5000,
        ssl: bool = false,
    };

    pub fn init(cfg: Config, callbacks: TransportCallbacks) Self {
        return Self{
            .config = cfg,
            .callbacks = callbacks,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.listen_socket) |sock| {
            posix.close(sock);
            self.listen_socket = null;
        }
    }

    /// 开始监听固定端口
    pub fn listen(self: *Self, local_port: u16) !void {
        if (local_port == 0) return;

        if (self.listen_socket) |sock| {
            posix.close(sock);
        }

        const local_addr = net.Address.initIp4(.{ 0, 0, 0, 0 }, local_port);
        self.listen_socket = try net_utils.createReuseUdpSocket(local_addr);

        log.info("UDP 端口映射监听启动: 端口 {d}", .{local_port});
    }

    pub fn connectAsync(self: *Self, info: *const types.TunnelTransportInfo) !?ITunnelConnection {
        log.logPunchStart(.udp_port_map, info.direction, info.local, info.remote);

        if (info.direction == .forward) {
            if (info.remote.port_map_wan == 0) {
                log.err("端口映射未配置", .{});
                log.logPunchFailed(.udp_port_map, "对方端口映射未配置");
                return TransportError.PortMapNotConfigured;
            }
            return try self.connectForward(info);
        } else {
            if (info.local.port_map_wan == 0) {
                log.err("本地端口映射未配置", .{});
                log.logPunchFailed(.udp_port_map, "本地端口映射未配置");
                return TransportError.PortMapNotConfigured;
            }
            return try self.waitConnect(info);
        }
    }

    fn connectForward(self: *Self, info: *const types.TunnelTransportInfo) !?ITunnelConnection {
        _ = self;
        log.debug("UDP 端口映射正向连接", .{});

        const sock = try net_utils.createReuseUdpSocket(info.local.local);
        errdefer posix.close(sock);

        // 构造目标地址 (使用端口映射端口)
        for (info.remote_endpoints) |ep| {
            var target_ep = ep;
            // 替换端口为映射端口
            if (target_ep.any.family == 2) { // AF_INET
                const addr_in = @as(*posix.sockaddr.in, @ptrCast(@alignCast(&target_ep.any)));
                addr_in.port = std.mem.nativeToBig(u16, info.remote.port_map_wan);
            } else if (target_ep.any.family == 10 or target_ep.any.family == 23) { // AF_INET6
                const addr_in6 = @as(*posix.sockaddr.in6, @ptrCast(@alignCast(&target_ep.any)));
                addr_in6.port = std.mem.nativeToBig(u16, info.remote.port_map_wan);
            } else {
                continue;
            }

            log.logConnectAttempt(target_ep, 1);

            // 发送标识
            var flag_buf: [256]u8 = undefined;
            const flag = std.fmt.bufPrint(&flag_buf, "{s}.udp.portmap.tunnel-{d}", .{ GLOBAL_STRING, info.flow_id }) catch continue;
            _ = posix.sendto(sock, flag, 0, &target_ep.any, target_ep.getOsSockLen()) catch continue;

            // 等待响应
            net_utils.setRecvTimeout(sock, 500) catch {};

            var buf: [256]u8 = undefined;
            var from_addr: posix.sockaddr = undefined;
            var from_len: posix.socklen_t = @sizeOf(posix.sockaddr);

            const recv_len = posix.recvfrom(sock, &buf, 0, &from_addr, &from_len) catch continue;

            if (recv_len > 0 and std.mem.eql(u8, buf[0..recv_len], flag)) {
                const remote_ep = net.Address{ .any = from_addr };
                log.info("UDP 端口映射连接成功! 远程端点: {any}", .{remote_ep});

                const connection = ITunnelConnection{
                    .info = types.TunnelConnectionInfo{
                        .remote_endpoint = net_utils.convertMappedAddress(remote_ep),
                        .remote_machine_id = info.remote.machine_id,
                        .remote_machine_name = info.remote.machine_name,
                        .transport_name = .udp_port_map,
                        .direction = info.direction,
                        .protocol_type = .udp,
                        .tunnel_type = .p2p,
                        .mode = .client,
                        .ssl = info.ssl,
                        .connected_at = std.time.timestamp(),
                    },
                    .socket = sock,
                    .connected = true,
                };

                log.logPunchSuccess(.udp_port_map, connection.info);
                return connection;
            }
        }

        log.logPunchFailed(.udp_port_map, "所有端点连接失败");
        return null;
    }

    fn waitConnect(self: *Self, info: *const types.TunnelTransportInfo) !?ITunnelConnection {
        const sock = self.listen_socket orelse return TransportError.PortMapNotConfigured;

        log.debug("UDP 端口映射等待连接", .{});

        net_utils.setRecvTimeout(sock, self.config.connect_timeout_ms) catch {};

        var buf: [256]u8 = undefined;
        var from_addr: posix.sockaddr = undefined;
        var from_len: posix.socklen_t = @sizeOf(posix.sockaddr);

        const recv_len = posix.recvfrom(sock, &buf, 0, &from_addr, &from_len) catch |e| {
            log.err("UDP 端口映射等待超时: {any}", .{e});
            log.logPunchFailed(.udp_port_map, "等待连接超时");
            return null;
        };

        if (recv_len > 0) {
            // 回复确认
            _ = posix.sendto(sock, buf[0..recv_len], 0, &from_addr, from_len) catch {};

            const remote_ep = net.Address{ .any = from_addr };
            log.info("UDP 端口映射收到连接! 远程端点: {any}", .{remote_ep});

            const connection = ITunnelConnection{
                .info = types.TunnelConnectionInfo{
                    .remote_endpoint = net_utils.convertMappedAddress(remote_ep),
                    .remote_machine_id = info.remote.machine_id,
                    .remote_machine_name = info.remote.machine_name,
                    .transport_name = .udp_port_map,
                    .direction = info.direction,
                    .protocol_type = .udp,
                    .tunnel_type = .p2p,
                    .mode = .server,
                    .ssl = info.ssl,
                    .connected_at = std.time.timestamp(),
                },
                .socket = sock,
                .connected = true,
            };

            log.logPunchSuccess(.udp_port_map, connection.info);
            return connection;
        }

        log.logPunchFailed(.udp_port_map, "收到空数据");
        return null;
    }

    pub fn onBegin(self: *Self, info: *const types.TunnelTransportInfo) !?ITunnelConnection {
        if (info.direction == .forward) {
            return try self.waitConnect(info);
        } else {
            return try self.connectForward(info);
        }
    }
};

/// ============================================================
/// TCP 端口映射传输
/// 基于端口映射的 TCP 打洞，需要配置固定端口
/// ============================================================
pub const TransportTcpPortMap = struct {
    const Self = @This();

    pub const NAME = "TcpPortMap";
    pub const LABEL = "TCP、端口映射";
    pub const PROTOCOL_TYPE = types.TunnelProtocolType.tcp;
    pub const ORDER: u8 = 2;

    config: Config,
    callbacks: TransportCallbacks,
    listen_socket: ?posix.socket_t = null,

    pub const Config = struct {
        connect_timeout_ms: u32 = 5000,
        ssl: bool = false,
    };

    pub fn init(cfg: Config, callbacks: TransportCallbacks) Self {
        return Self{
            .config = cfg,
            .callbacks = callbacks,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.listen_socket) |sock| {
            posix.close(sock);
            self.listen_socket = null;
        }
    }

    /// 开始监听固定端口
    pub fn listen(self: *Self, local_port: u16) !void {
        if (local_port == 0) return;

        if (self.listen_socket) |sock| {
            posix.close(sock);
        }

        const local_addr = net.Address.initIp4(.{ 0, 0, 0, 0 }, local_port);
        const sock = try net_utils.createReuseTcpSocket(local_addr);
        try posix.listen(sock, 128);

        self.listen_socket = sock;

        log.info("TCP 端口映射监听启动: 端口 {d}", .{local_port});
    }

    pub fn connectAsync(self: *Self, info: *const types.TunnelTransportInfo) !?ITunnelConnection {
        log.logPunchStart(.tcp_port_map, info.direction, info.local, info.remote);

        if (info.direction == .forward) {
            if (info.remote.port_map_wan == 0) {
                log.err("端口映射未配置", .{});
                log.logPunchFailed(.tcp_port_map, "对方端口映射未配置");
                return TransportError.PortMapNotConfigured;
            }
            return try self.connectForward(info);
        } else {
            if (info.local.port_map_wan == 0) {
                log.err("本地端口映射未配置", .{});
                log.logPunchFailed(.tcp_port_map, "本地端口映射未配置");
                return TransportError.PortMapNotConfigured;
            }
            return try self.waitConnect(info);
        }
    }

    fn connectForward(self: *Self, info: *const types.TunnelTransportInfo) !?ITunnelConnection {
        _ = self;
        log.debug("TCP 端口映射正向连接", .{});

        for (info.remote_endpoints) |ep| {
            var target_ep = ep;
            // 替换端口为映射端口
            if (target_ep.any.family == 2) { // AF_INET
                const addr_in = @as(*posix.sockaddr.in, @ptrCast(@alignCast(&target_ep.any)));
                addr_in.port = std.mem.nativeToBig(u16, info.remote.port_map_wan);
            } else if (target_ep.any.family == 10 or target_ep.any.family == 23) { // AF_INET6
                const addr_in6 = @as(*posix.sockaddr.in6, @ptrCast(@alignCast(&target_ep.any)));
                addr_in6.port = std.mem.nativeToBig(u16, info.remote.port_map_wan);
            } else {
                continue;
            }

            log.logConnectAttempt(target_ep, 1);

            const sock = try net_utils.createReuseTcpSocket(info.local.local);
            errdefer posix.close(sock);

            net_utils.setKeepAlive(sock, true) catch {};

            posix.connect(sock, &target_ep.any, target_ep.getOsSockLen()) catch {
                posix.close(sock);
                continue;
            };

            // 发送标识
            var flag_buf2: [64]u8 = undefined;
            const flag = std.fmt.bufPrint(&flag_buf2, "{d}-{d}", .{ info.flow_id, info.flow_id }) catch continue;
            _ = posix.send(sock, flag, 0) catch {
                posix.close(sock);
                continue;
            };

            // 等待响应
            var buf: [64]u8 = undefined;
            _ = posix.recv(sock, &buf, 0) catch {
                posix.close(sock);
                continue;
            };

            log.info("TCP 端口映射连接成功! 远程端点: {any}", .{target_ep});

            const connection = ITunnelConnection{
                .info = types.TunnelConnectionInfo{
                    .remote_endpoint = net_utils.convertMappedAddress(target_ep),
                    .remote_machine_id = info.remote.machine_id,
                    .remote_machine_name = info.remote.machine_name,
                    .transport_name = .tcp_port_map,
                    .direction = info.direction,
                    .protocol_type = .tcp,
                    .tunnel_type = .p2p,
                    .mode = .client,
                    .ssl = info.ssl,
                    .connected_at = std.time.timestamp(),
                },
                .socket = sock,
                .connected = true,
            };

            log.logPunchSuccess(.tcp_port_map, connection.info);
            return connection;
        }

        log.logPunchFailed(.tcp_port_map, "所有端点连接失败");
        return null;
    }

    fn waitConnect(self: *Self, info: *const types.TunnelTransportInfo) !?ITunnelConnection {
        const listen_sock = self.listen_socket orelse return TransportError.PortMapNotConfigured;

        log.debug("TCP 端口映射等待连接", .{});

        net_utils.setRecvTimeout(listen_sock, self.config.connect_timeout_ms) catch {};

        var client_addr: posix.sockaddr = undefined;
        var client_len: posix.socklen_t = @sizeOf(posix.sockaddr);

        const client_sock = posix.accept(listen_sock, &client_addr, &client_len, 0) catch |e| {
            log.err("TCP 端口映射等待超时: {any}", .{e});
            log.logPunchFailed(.tcp_port_map, "等待连接超时");
            return null;
        };

        // 接收标识
        var buf: [64]u8 = undefined;
        const recv_len = posix.recv(client_sock, &buf, 0) catch {
            posix.close(client_sock);
            return null;
        };

        if (recv_len > 0) {
            // 回复确认
            _ = posix.send(client_sock, buf[0..recv_len], 0) catch {};

            const remote_ep = net.Address{ .any = client_addr };
            log.info("TCP 端口映射收到连接! 远程端点: {any}", .{remote_ep});

            const connection = ITunnelConnection{
                .info = types.TunnelConnectionInfo{
                    .remote_endpoint = net_utils.convertMappedAddress(remote_ep),
                    .remote_machine_id = info.remote.machine_id,
                    .remote_machine_name = info.remote.machine_name,
                    .transport_name = .tcp_port_map,
                    .direction = info.direction,
                    .protocol_type = .tcp,
                    .tunnel_type = .p2p,
                    .mode = .server,
                    .ssl = info.ssl,
                    .connected_at = std.time.timestamp(),
                },
                .socket = client_sock,
                .connected = true,
            };

            log.logPunchSuccess(.tcp_port_map, connection.info);
            return connection;
        }

        log.logPunchFailed(.tcp_port_map, "收到空数据");
        posix.close(client_sock);
        return null;
    }

    pub fn onBegin(self: *Self, info: *const types.TunnelTransportInfo) !?ITunnelConnection {
        if (info.direction == .forward) {
            return try self.waitConnect(info);
        } else {
            return try self.connectForward(info);
        }
    }
};

/// ============================================================
/// MsQuic 传输 (暂未实现)
/// 与 UDP 打洞同理，只是打洞成功后多包装一个 QUIC，用于保证消息准确到达
/// ============================================================
pub const TransportMsQuic = struct {
    const Self = @This();

    pub const NAME = "MsQuic";
    pub const LABEL = "MsQuic，win10+、linux";
    pub const PROTOCOL_TYPE = types.TunnelProtocolType.quic;
    pub const ORDER: u8 = 255;

    callbacks: TransportCallbacks,

    pub fn init(callbacks: TransportCallbacks) Self {
        return Self{
            .callbacks = callbacks,
        };
    }

    pub fn connectAsync(self: *Self, info: *const types.TunnelTransportInfo) !?ITunnelConnection {
        _ = self;
        _ = info;
        log.warn("MsQuic 传输暂未实现", .{});
        return TransportError.Unsupported;
    }

    pub fn onBegin(self: *Self, info: *const types.TunnelTransportInfo) !?ITunnelConnection {
        return self.connectAsync(info);
    }
};

/// 传输管理器
pub const TransportManager = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    callbacks: TransportCallbacks,

    // 各种传输方式
    udp: TransportUdp,
    udp_p2p_nat: TransportUdpP2PNAT,
    tcp_p2p_nat: TransportTcpP2PNAT,
    tcp_nutssb: TransportTcpNutssb,
    udp_port_map: TransportUdpPortMap,
    tcp_port_map: TransportTcpPortMap,
    msquic: TransportMsQuic,

    pub fn init(allocator: std.mem.Allocator, callbacks: TransportCallbacks) Self {
        return Self{
            .allocator = allocator,
            .callbacks = callbacks,
            .udp = TransportUdp.init(.{}, callbacks),
            .udp_p2p_nat = TransportUdpP2PNAT.init(.{}, callbacks),
            .tcp_p2p_nat = TransportTcpP2PNAT.init(.{}, callbacks),
            .tcp_nutssb = TransportTcpNutssb.init(.{}, callbacks),
            .udp_port_map = TransportUdpPortMap.init(.{}, callbacks),
            .tcp_port_map = TransportTcpPortMap.init(.{}, callbacks),
            .msquic = TransportMsQuic.init(callbacks),
        };
    }

    pub fn deinit(self: *Self) void {
        self.udp_port_map.deinit();
        self.tcp_port_map.deinit();
    }

    /// 根据传输方式名称获取对应的传输器
    pub fn getTransport(self: *Self, transport_type: types.TransportType) union(enum) {
        udp: *TransportUdp,
        udp_p2p_nat: *TransportUdpP2PNAT,
        tcp_p2p_nat: *TransportTcpP2PNAT,
        tcp_nutssb: *TransportTcpNutssb,
        udp_port_map: *TransportUdpPortMap,
        tcp_port_map: *TransportTcpPortMap,
        msquic: *TransportMsQuic,
    } {
        return switch (transport_type) {
            .udp => .{ .udp = &self.udp },
            .udp_p2p_nat => .{ .udp_p2p_nat = &self.udp_p2p_nat },
            .tcp_p2p_nat => .{ .tcp_p2p_nat = &self.tcp_p2p_nat },
            .tcp_nutssb => .{ .tcp_nutssb = &self.tcp_nutssb },
            .udp_port_map => .{ .udp_port_map = &self.udp_port_map },
            .tcp_port_map => .{ .tcp_port_map = &self.tcp_port_map },
            .msquic => .{ .msquic = &self.msquic },
        };
    }

    /// 使用指定传输方式连接
    pub fn connect(self: *Self, transport_type: types.TransportType, info: *const types.TunnelTransportInfo) !?ITunnelConnection {
        return switch (transport_type) {
            .udp => try self.udp.connectAsync(info),
            .udp_p2p_nat => try self.udp_p2p_nat.connectAsync(info),
            .tcp_p2p_nat => try self.tcp_p2p_nat.connectAsync(info),
            .tcp_nutssb => try self.tcp_nutssb.connectAsync(info),
            .udp_port_map => try self.udp_port_map.connectAsync(info),
            .tcp_port_map => try self.tcp_port_map.connectAsync(info),
            .msquic => try self.msquic.connectAsync(info),
        };
    }
};

test "TransportUdp name and label" {
    try std.testing.expectEqualStrings("Udp", TransportUdp.NAME);
    try std.testing.expectEqualStrings("UDP、非常纯", TransportUdp.LABEL);
}

test "TransportUdpP2PNAT name and label" {
    try std.testing.expectEqualStrings("UdpP2PNAT", TransportUdpP2PNAT.NAME);
    try std.testing.expectEqualStrings("UDP、同时打开", TransportUdpP2PNAT.LABEL);
    try std.testing.expectEqual(types.TunnelProtocolType.udp, TransportUdpP2PNAT.PROTOCOL_TYPE);
}

test "TransportManager init" {
    const allocator = std.testing.allocator;
    var manager = TransportManager.init(allocator, .{});
    defer manager.deinit();

    // 验证可以获取各种传输器
    _ = manager.getTransport(.udp);
    _ = manager.getTransport(.udp_p2p_nat);
    _ = manager.getTransport(.tcp_p2p_nat);
    _ = manager.getTransport(.tcp_nutssb);
}
