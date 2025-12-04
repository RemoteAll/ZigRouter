//! QUIC 打洞传输实现
//! 将 QUIC 协议集成到 NAT 穿透框架中

const std = @import("std");
const Allocator = std.mem.Allocator;
const net = std.net;
const posix = std.posix;

const types = @import("types.zig");
const transport = @import("transport.zig");
const quic = @import("../quic/quic.zig");

const QuicClient = quic.QuicClient;
const QuicServer = quic.QuicServer;
const ServerConnection = quic.ServerConnection;

/// QUIC 传输错误
pub const QuicTransportError = error{
    /// 连接超时
    ConnectionTimeout,
    /// 握手失败
    HandshakeFailed,
    /// 对端关闭
    ConnectionClosed,
    /// 流错误
    StreamError,
    /// 无效状态
    InvalidState,
    /// 发送失败
    SendFailed,
    /// 接收失败
    ReceiveFailed,
};

/// QUIC 打洞传输配置
pub const QuicHolePunchConfig = struct {
    /// 本地绑定地址
    local_address: ?net.Address = null,
    /// 目标地址
    target_address: net.Address,
    /// ALPN 协议
    alpn: []const u8 = "linker-tunnel",
    /// 连接超时（毫秒）
    connect_timeout_ms: u64 = 10000,
    /// 空闲超时（毫秒）
    idle_timeout_ms: u64 = 30000,
    /// 是否作为发起方
    is_initiator: bool = true,
    /// 打洞尝试次数
    punch_attempts: u32 = 3,
    /// 打洞间隔（毫秒）
    punch_interval_ms: u64 = 100,
};

/// QUIC 打洞传输状态
pub const QuicHolePunchState = enum {
    /// 初始状态
    idle,
    /// 正在打洞
    punching,
    /// 正在握手
    handshaking,
    /// 已连接
    connected,
    /// 已关闭
    closed,
    /// 错误
    failed,
};

/// QUIC 打洞传输
pub const QuicHolePunchTransport = struct {
    allocator: Allocator,
    config: QuicHolePunchConfig,
    state: QuicHolePunchState = .idle,

    /// QUIC 客户端（发起方）
    client: ?QuicClient = null,
    /// QUIC 服务端（被动方）
    server: ?QuicServer = null,
    /// 服务端连接（被动方接受的连接）
    server_conn: ?*ServerConnection = null,

    /// 当前流 ID
    current_stream_id: u64 = 0,

    /// 统计信息
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    packets_sent: u64 = 0,
    packets_received: u64 = 0,

    /// 错误信息
    last_error: ?[]const u8 = null,

    pub fn init(allocator: Allocator, config: QuicHolePunchConfig) QuicHolePunchTransport {
        return QuicHolePunchTransport{
            .allocator = allocator,
            .config = config,
        };
    }

    pub fn deinit(self: *QuicHolePunchTransport) void {
        self.close();
    }

    /// 开始打洞并建立连接
    pub fn connect(self: *QuicHolePunchTransport) !void {
        if (self.state != .idle) return error.InvalidState;

        self.state = .punching;

        if (self.config.is_initiator) {
            try self.connectAsInitiator();
        } else {
            try self.connectAsResponder();
        }
    }

    /// 作为发起方连接
    fn connectAsInitiator(self: *QuicHolePunchTransport) !void {
        // 创建 QUIC 客户端
        self.client = QuicClient.init(self.allocator, .{
            .server_address = self.config.target_address,
            .alpn = self.config.alpn,
            .connect_timeout_ms = self.config.connect_timeout_ms,
            .idle_timeout_ms = self.config.idle_timeout_ms,
        });

        // 设置传输参数
        self.client.?.config.transport_params = quic.TransportParameters.defaultClient();

        self.state = .handshaking;

        // 发起连接
        try self.client.?.connect();

        // 等待握手完成
        const start_time = std.time.milliTimestamp();
        while (self.state == .handshaking) {
            const event = self.client.?.recv() catch |err| {
                if (err == error.WouldBlock) {
                    // 检查超时
                    const elapsed: u64 = @intCast(std.time.milliTimestamp() - start_time);
                    if (elapsed > self.config.connect_timeout_ms) {
                        self.state = .failed;
                        self.last_error = "Connection timeout";
                        return error.ConnectionTimeout;
                    }
                    std.time.sleep(1_000_000); // 1ms
                    continue;
                }
                self.state = .failed;
                return err;
            };

            if (event) |e| {
                switch (e) {
                    .connected, .handshake_completed => {
                        self.state = .connected;
                        // 打开默认流
                        self.current_stream_id = try self.client.?.openStream(true);
                        return;
                    },
                    .connection_closed => {
                        self.state = .failed;
                        self.last_error = "Connection closed by peer";
                        return error.ConnectionClosed;
                    },
                    else => {},
                }
            }
        }
    }

    /// 作为响应方连接
    fn connectAsResponder(self: *QuicHolePunchTransport) !void {
        // 创建 QUIC 服务端
        const bind_addr = self.config.local_address orelse try net.Address.parseIp4("0.0.0.0", 0);

        self.server = QuicServer.init(self.allocator, .{
            .bind_address = bind_addr,
            .alpn = self.config.alpn,
            .idle_timeout_ms = self.config.idle_timeout_ms,
        });

        // 开始监听
        try self.server.?.listen();

        self.state = .handshaking;

        // 同时发送打洞包到目标地址
        try self.sendPunchPackets();

        // 等待连接
        const start_time = std.time.milliTimestamp();
        while (self.state == .handshaking) {
            const event = self.server.?.accept() catch |err| {
                if (err == error.WouldBlock) {
                    const elapsed: u64 = @intCast(std.time.milliTimestamp() - start_time);
                    if (elapsed > self.config.connect_timeout_ms) {
                        self.state = .failed;
                        self.last_error = "Connection timeout";
                        return error.ConnectionTimeout;
                    }
                    std.time.sleep(1_000_000); // 1ms
                    continue;
                }
                self.state = .failed;
                return err;
            };

            if (event) |e| {
                switch (e) {
                    .new_connection => |conn| {
                        self.server_conn = conn;
                    },
                    .handshake_completed => |conn| {
                        self.server_conn = conn;
                        self.state = .connected;
                        return;
                    },
                    .connection_closed => {
                        self.state = .failed;
                        self.last_error = "Connection closed by peer";
                        return error.ConnectionClosed;
                    },
                    else => {},
                }
            }
        }
    }

    /// 发送打洞包
    fn sendPunchPackets(self: *QuicHolePunchTransport) !void {
        if (self.server == null) return;

        const sock = self.server.?.socket orelse return;

        // 发送几个 QUIC Initial 包作为打洞包
        var punch_data: [1200]u8 = undefined;

        // 构造简单的打洞包（可以是空的 UDP 包或特殊标记）
        @memset(&punch_data, 0);
        punch_data[0] = 0xFF; // 标记为打洞包

        for (0..self.config.punch_attempts) |_| {
            _ = posix.sendto(
                sock,
                &punch_data,
                0,
                &self.config.target_address.any,
                self.config.target_address.getOsSockLen(),
            ) catch continue;

            std.time.sleep(self.config.punch_interval_ms * 1_000_000);
        }
    }

    /// 发送数据
    pub fn send(self: *QuicHolePunchTransport, data: []const u8) !usize {
        if (self.state != .connected) return error.InvalidState;

        if (self.client) |*c| {
            try c.send(self.current_stream_id, data, false);
            self.bytes_sent += data.len;
            self.packets_sent += 1;
            return data.len;
        }

        if (self.server_conn) |conn| {
            try conn.send(self.server.?, 0, data, false);
            self.bytes_sent += data.len;
            self.packets_sent += 1;
            return data.len;
        }

        return error.InvalidState;
    }

    /// 接收数据
    pub fn recv(self: *QuicHolePunchTransport, buf: []u8) !usize {
        if (self.state != .connected) return error.InvalidState;

        if (self.client) |*c| {
            const event = try c.recv();
            if (event) |e| {
                switch (e) {
                    .data_received => |dr| {
                        const len = @min(buf.len, dr.data.len);
                        @memcpy(buf[0..len], dr.data[0..len]);
                        self.bytes_received += len;
                        self.packets_received += 1;
                        return len;
                    },
                    .connection_closed => {
                        self.state = .closed;
                        return error.ConnectionClosed;
                    },
                    else => {},
                }
            }
            return 0;
        }

        if (self.server) |*s| {
            const event = try s.accept();
            if (event) |e| {
                switch (e) {
                    .data_received => |dr| {
                        const len = @min(buf.len, dr.data.len);
                        @memcpy(buf[0..len], dr.data[0..len]);
                        self.bytes_received += len;
                        self.packets_received += 1;
                        return len;
                    },
                    .connection_closed => {
                        self.state = .closed;
                        return error.ConnectionClosed;
                    },
                    else => {},
                }
            }
            return 0;
        }

        return 0;
    }

    /// 关闭连接
    pub fn close(self: *QuicHolePunchTransport) void {
        if (self.client) |*c| {
            c.close(0, "Normal closure") catch {};
            c.deinit();
            self.client = null;
        }

        if (self.server_conn) |conn| {
            conn.close(self.server.?, 0, "Normal closure") catch {};
        }

        if (self.server) |*s| {
            s.deinit();
            self.server = null;
        }

        self.state = .closed;
    }

    /// 获取连接信息
    pub fn getConnectionInfo(self: *QuicHolePunchTransport) types.TunnelConnectionInfo {
        return types.TunnelConnectionInfo{
            .remote_endpoint = self.config.target_address,
            .transport_name = .msquic,
            .direction = if (self.config.is_initiator) .forward else .reverse,
            .protocol_type = .quic,
            .tunnel_type = .p2p,
            .mode = if (self.config.is_initiator) .client else .server,
            .connected_at = std.time.milliTimestamp(),
        };
    }

    /// 是否已连接
    pub fn isConnected(self: *QuicHolePunchTransport) bool {
        return self.state == .connected;
    }

    /// 获取统计信息
    pub fn getStats(self: *QuicHolePunchTransport) struct {
        bytes_sent: u64,
        bytes_received: u64,
        packets_sent: u64,
        packets_received: u64,
    } {
        return .{
            .bytes_sent = self.bytes_sent,
            .bytes_received = self.bytes_received,
            .packets_sent = self.packets_sent,
            .packets_received = self.packets_received,
        };
    }
};

/// QUIC 打洞会话
/// 用于管理双方的 QUIC 打洞过程
pub const QuicHolePunchSession = struct {
    allocator: Allocator,

    /// 本方传输
    transport: QuicHolePunchTransport,

    /// 会话 ID
    session_id: [16]u8 = undefined,

    /// 开始时间
    start_time: i64 = 0,

    /// 是否成功
    success: bool = false,

    pub fn init(allocator: Allocator, config: QuicHolePunchConfig) QuicHolePunchSession {
        var session = QuicHolePunchSession{
            .allocator = allocator,
            .transport = QuicHolePunchTransport.init(allocator, config),
        };

        // 生成会话 ID
        var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
        prng.random().bytes(&session.session_id);

        return session;
    }

    pub fn deinit(self: *QuicHolePunchSession) void {
        self.transport.deinit();
    }

    /// 执行打洞
    pub fn punch(self: *QuicHolePunchSession) !void {
        self.start_time = std.time.milliTimestamp();

        try self.transport.connect();

        if (self.transport.state == .connected) {
            self.success = true;
        }
    }

    /// 获取打洞耗时（毫秒）
    pub fn getElapsedMs(self: *QuicHolePunchSession) i64 {
        if (self.start_time == 0) return 0;
        return std.time.milliTimestamp() - self.start_time;
    }
};

/// 创建 QUIC 打洞传输（简化接口）
pub fn createQuicTransport(
    allocator: Allocator,
    target_addr: net.Address,
    is_initiator: bool,
) QuicHolePunchTransport {
    return QuicHolePunchTransport.init(allocator, .{
        .target_address = target_addr,
        .is_initiator = is_initiator,
    });
}

// ============ 单元测试 ============

test "quic transport init" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const addr = try net.Address.parseIp4("127.0.0.1", 4433);
    var transport_inst = QuicHolePunchTransport.init(allocator, .{
        .target_address = addr,
        .is_initiator = true,
    });
    defer transport_inst.deinit();

    try testing.expectEqual(QuicHolePunchState.idle, transport_inst.state);
    try testing.expect(!transport_inst.isConnected());
}

test "quic session init" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const addr = try net.Address.parseIp4("127.0.0.1", 4433);
    var session = QuicHolePunchSession.init(allocator, .{
        .target_address = addr,
        .is_initiator = true,
    });
    defer session.deinit();

    try testing.expect(!session.success);
    try testing.expectEqual(@as(i64, 0), session.start_time);
}
