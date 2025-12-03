//! 打洞信令服务器
//! 负责协调客户端之间的打洞过程
//! 参考 C# linker 项目的实现

const std = @import("std");
const net = std.net;
const posix = std.posix;
const types = @import("types.zig");
const log = @import("log.zig");
const net_utils = @import("net_utils.zig");
const protocol = @import("protocol.zig");
const stun = @import("stun.zig");

/// 客户端信息
pub const ClientInfo = struct {
    /// 客户端 ID
    machine_id: []const u8,
    /// 客户端名称
    machine_name: []const u8,
    /// NAT 类型
    nat_type: types.NatType = .unknown,
    /// 本地地址
    local_addr: net.Address,
    /// 公网地址
    public_addr: ?net.Address = null,
    /// socket
    socket: posix.socket_t,
    /// 连接时间
    connected_at: i64,
    /// 最后活动时间
    last_active: i64,
    /// 端口映射端口
    port_map_wan: u16 = 0,
    /// 路由级别
    route_level: u8 = 8,
};

/// 打洞服务器配置
pub const ServerConfig = struct {
    /// 监听端口
    listen_port: u16 = 7891,
    /// 监听地址
    listen_addr: []const u8 = "0.0.0.0",
    /// 最大客户端数
    max_clients: usize = 1024,
    /// 心跳间隔 (秒)
    heartbeat_interval: u32 = 30,
    /// 客户端超时 (秒)
    client_timeout: u32 = 120,
};

/// 打洞服务器
pub const PunchServer = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    config: ServerConfig,

    /// 监听 socket
    listen_socket: ?posix.socket_t = null,

    /// 已连接的客户端
    clients: std.StringHashMap(ClientInfo),

    /// 运行状态
    running: bool = false,

    /// 统计信息
    stats: struct {
        total_connections: u64 = 0,
        total_punch_requests: u64 = 0,
        successful_punches: u64 = 0,
        failed_punches: u64 = 0,
    } = .{},

    pub fn init(allocator: std.mem.Allocator, config: ServerConfig) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .clients = std.StringHashMap(ClientInfo).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.stop();
        self.clients.deinit();
    }

    /// 启动服务器
    pub fn start(self: *Self) !void {
        if (self.running) {
            log.warn("服务器已在运行中", .{});
            return;
        }

        log.info("========================================", .{});
        log.info("  打洞信令服务器启动中...", .{});
        log.info("========================================", .{});

        // 解析监听地址
        const listen_addr = try net.Address.parseIp4(self.config.listen_addr, self.config.listen_port);

        // 创建监听 socket
        const sock = try posix.socket(
            posix.AF.INET,
            posix.SOCK.STREAM,
            posix.IPPROTO.TCP,
        );
        errdefer posix.close(sock);

        // 设置选项
        try net_utils.setReuseAddr(sock, true);

        // 绑定
        try posix.bind(sock, &listen_addr.any, listen_addr.getOsSockLen());

        // 监听
        try posix.listen(sock, 128);

        self.listen_socket = sock;
        self.running = true;

        log.info("服务器已启动，监听地址: {s}:{d}", .{ self.config.listen_addr, self.config.listen_port });
        log.info("等待客户端连接...", .{});
    }

    /// 停止服务器
    pub fn stop(self: *Self) void {
        if (!self.running) return;

        log.info("服务器正在停止...", .{});

        // 关闭所有客户端连接
        var iter = self.clients.iterator();
        while (iter.next()) |entry| {
            posix.close(entry.value_ptr.socket);
        }
        self.clients.clearAndFree();

        // 关闭监听 socket
        if (self.listen_socket) |sock| {
            posix.close(sock);
            self.listen_socket = null;
        }

        self.running = false;
        log.info("服务器已停止", .{});
    }

    /// 运行服务器主循环
    pub fn run(self: *Self) !void {
        if (!self.running) {
            try self.start();
        }

        const listen_sock = self.listen_socket orelse return;

        while (self.running) {
            // 等待新连接
            var client_addr: posix.sockaddr = undefined;
            var client_len: posix.socklen_t = @sizeOf(posix.sockaddr);

            const client_sock = posix.accept(listen_sock, &client_addr, &client_len, 0) catch |e| {
                if (e == error.WouldBlock) {
                    std.Thread.sleep(10 * std.time.ns_per_ms);
                    continue;
                }
                log.err("accept 错误: {any}", .{e});
                continue;
            };

            const client_ep = net.Address{ .any = client_addr };
            log.info("新连接: {any}", .{client_ep});

            // 处理客户端
            self.handleClient(client_sock, client_ep) catch |e| {
                log.err("处理客户端错误: {any}", .{e});
                posix.close(client_sock);
            };
        }
    }

    /// 处理客户端连接
    fn handleClient(self: *Self, sock: posix.socket_t, client_ep: net.Address) !void {
        self.stats.total_connections += 1;

        // 接收注册消息
        var buf: [4096]u8 = undefined;
        const recv_len = posix.recv(sock, &buf, 0) catch |e| {
            log.err("接收注册消息失败: {any}", .{e});
            return;
        };

        if (recv_len < protocol.MessageHeader.SIZE) {
            log.err("消息太短", .{});
            return;
        }

        // 解析消息头
        const header = protocol.MessageHeader.parse(buf[0..protocol.MessageHeader.SIZE]) catch |e| {
            log.err("解析消息头错误: {any}", .{e});
            return;
        };

        if (header.msg_type != .register) {
            log.err("第一条消息必须是注册消息，收到: {any}", .{header.msg_type});
            return;
        }

        // 解析注册消息
        const payload = buf[protocol.MessageHeader.SIZE..recv_len];
        const peer_info = protocol.PeerInfo.parse(payload, self.allocator) catch |e| {
            log.err("解析注册消息失败: {any}", .{e});
            return;
        };

        // 创建客户端信息
        const client_info = ClientInfo{
            .machine_id = try self.allocator.dupe(u8, peer_info.machine_id),
            .machine_name = try self.allocator.dupe(u8, peer_info.machine_name),
            .nat_type = peer_info.nat_type,
            .local_addr = peer_info.local_endpoint,
            .public_addr = client_ep,
            .socket = sock,
            .connected_at = std.time.timestamp(),
            .last_active = std.time.timestamp(),
            .port_map_wan = peer_info.port_map_wan,
            .route_level = peer_info.route_level,
        };

        // 存储客户端信息
        try self.clients.put(client_info.machine_id, client_info);

        log.info("========================================", .{});
        log.info("  客户端注册成功", .{});
        log.info("  ID: {s}", .{client_info.machine_id});
        log.info("  名称: {s}", .{client_info.machine_name});
        log.info("  NAT 类型: {s}", .{client_info.nat_type.description()});
        log.info("  本地地址: {any}", .{client_info.local_addr});
        log.info("  公网地址: {any}", .{client_ep});
        log.info("  端口映射: {d}", .{client_info.port_map_wan});
        log.info("  当前在线客户端数: {d}", .{self.clients.count()});
        log.info("========================================", .{});

        // 发送注册成功响应
        try self.sendRegisterResponse(sock, true, client_info.machine_id);

        // 进入消息处理循环
        self.handleClientMessages(sock, client_info.machine_id) catch |e| {
            log.err("客户端消息处理错误: {any}", .{e});
        };

        // 客户端断开，清理
        log.info("客户端断开: {s}", .{client_info.machine_id});
        _ = self.clients.remove(client_info.machine_id);
    }

    /// 处理客户端消息
    fn handleClientMessages(self: *Self, sock: posix.socket_t, machine_id: []const u8) !void {
        var buf: [4096]u8 = undefined;

        while (self.running) {
            const recv_len = posix.recv(sock, &buf, 0) catch |e| {
                if (e == error.WouldBlock) {
                    std.Thread.sleep(10 * std.time.ns_per_ms);
                    continue;
                }
                return e;
            };

            if (recv_len == 0) {
                // 连接关闭
                return;
            }

            if (recv_len < protocol.MessageHeader.SIZE) {
                continue;
            }

            // 更新活动时间
            if (self.clients.getPtr(machine_id)) |client| {
                client.last_active = std.time.timestamp();
            }

            // 解析消息
            const header = protocol.MessageHeader.parse(buf[0..protocol.MessageHeader.SIZE]) catch continue;
            const msg_payload = buf[protocol.MessageHeader.SIZE..recv_len];

            switch (header.msg_type) {
                .heartbeat => {
                    try self.sendHeartbeatResponse(sock);
                },
                .punch_request => {
                    try self.handlePunchRequest(sock, machine_id, msg_payload);
                },
                .list_peers => {
                    try self.sendPeerList(sock, machine_id);
                },
                else => {
                    log.debug("未知消息类型: {any}", .{header.msg_type});
                },
            }
        }
    }

    /// 发送注册响应
    fn sendRegisterResponse(self: *Self, sock: posix.socket_t, success: bool, machine_id: []const u8) !void {
        _ = self;
        var buf: [256]u8 = undefined;
        var stream = std.io.fixedBufferStream(&buf);
        const writer = stream.writer();

        try writer.writeByte(if (success) 1 else 0);
        try writer.writeInt(u16, @intCast(machine_id.len), .big);
        try writer.writeAll(machine_id);

        const payload = stream.getWritten();

        const msg_header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .register_response,
            .data_length = @intCast(payload.len),
            .sequence = 0,
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try msg_header.serialize(&header_buf);

        _ = posix.send(sock, &header_buf, 0) catch return;
        _ = posix.send(sock, payload, 0) catch return;
    }

    /// 发送心跳响应
    fn sendHeartbeatResponse(self: *Self, sock: posix.socket_t) !void {
        _ = self;
        const msg_header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .heartbeat_response,
            .data_length = 0,
            .sequence = 0,
        };

        var buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try msg_header.serialize(&buf);
        _ = posix.send(sock, &buf, 0) catch {};
    }

    /// 处理打洞请求
    fn handlePunchRequest(self: *Self, sock: posix.socket_t, from_id: []const u8, payload: []const u8) !void {
        self.stats.total_punch_requests += 1;

        const request = protocol.PunchRequest.parse(payload) orelse {
            log.err("解析打洞请求失败", .{});
            return;
        };

        log.info("========================================", .{});
        log.info("  收到打洞请求", .{});
        log.info("  发起方: {s}", .{from_id});
        log.info("  目标方: {s}", .{request.target_machine_id});
        log.info("  传输方式: {s}", .{request.transport.description()});
        log.info("========================================", .{});

        // 查找目标客户端
        const target = self.clients.get(request.target_machine_id);
        if (target == null) {
            log.err("目标客户端不在线: {s}", .{request.target_machine_id});
            try self.sendPunchResponse(sock, false, .peer_not_found, null);
            self.stats.failed_punches += 1;
            return;
        }

        const target_client = target.?;
        const from_client = self.clients.get(from_id) orelse {
            log.err("发起方客户端信息丢失", .{});
            return;
        };

        // 检查 NAT 类型兼容性
        const can_p2p = from_client.nat_type.canP2P(target_client.nat_type);
        if (!can_p2p and request.transport != .tcp_port_map and request.transport != .udp_port_map) {
            log.warn("NAT 类型不兼容，可能无法打洞成功", .{});
            log.warn("  发起方 NAT: {s}", .{from_client.nat_type.description()});
            log.warn("  目标方 NAT: {s}", .{target_client.nat_type.description()});
        }

        // 发送打洞成功响应（实际成功需要后续确认）
        try self.sendPunchResponse(sock, true, .success, null);

        log.info("已通知双方开始打洞", .{});
    }

    /// 发送打洞响应
    fn sendPunchResponse(self: *Self, sock: posix.socket_t, success: bool, error_code: protocol.ErrorCode, connection_info: ?[]const u8) !void {
        _ = self;
        var buf: [256]u8 = undefined;
        var stream = std.io.fixedBufferStream(&buf);
        const writer = stream.writer();

        try writer.writeByte(if (success) 1 else 0);
        try writer.writeInt(u16, @intFromEnum(error_code), .big);

        if (connection_info) |info| {
            try writer.writeAll(info);
        }

        const payload = stream.getWritten();

        const msg_header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .punch_response,
            .data_length = @intCast(payload.len),
            .sequence = 0,
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try msg_header.serialize(&header_buf);

        _ = posix.send(sock, &header_buf, 0) catch return;
        _ = posix.send(sock, payload, 0) catch return;
    }

    /// 发送在线客户端列表
    fn sendPeerList(self: *Self, sock: posix.socket_t, exclude_id: []const u8) !void {
        var buf: [4096]u8 = undefined;
        var stream = std.io.fixedBufferStream(&buf);
        const writer = stream.writer();

        var count: u16 = 0;
        try writer.writeInt(u16, 0, .big); // 占位符

        var iter = self.clients.iterator();
        while (iter.next()) |entry| {
            if (std.mem.eql(u8, entry.key_ptr.*, exclude_id)) continue;

            const client = entry.value_ptr;
            try writer.writeInt(u16, @intCast(client.machine_id.len), .big);
            try writer.writeAll(client.machine_id);
            try writer.writeInt(u16, @intCast(client.machine_name.len), .big);
            try writer.writeAll(client.machine_name);
            try writer.writeByte(@intFromEnum(client.nat_type));
            count += 1;
        }

        // 回写数量
        const written = stream.getWritten();
        const count_bytes = std.mem.toBytes(std.mem.nativeToBig(u16, count));
        @memcpy(written[0..2], &count_bytes);

        const msg_header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .list_peers_response,
            .data_length = @intCast(written.len),
            .sequence = 0,
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try msg_header.serialize(&header_buf);

        _ = posix.send(sock, &header_buf, 0) catch return;
        _ = posix.send(sock, written, 0) catch return;
    }

    /// 获取服务器统计信息
    pub fn getStats(self: *const Self) @TypeOf(self.stats) {
        return self.stats;
    }

    /// 获取在线客户端数量
    pub fn getClientCount(self: *const Self) usize {
        return self.clients.count();
    }
};

/// 服务器入口函数
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 解析命令行参数
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var config = ServerConfig{};

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--port")) {
            if (i + 1 < args.len) {
                config.listen_port = std.fmt.parseInt(u16, args[i + 1], 10) catch 7891;
                i += 1;
            }
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printUsage();
            return;
        }
    }

    var server = PunchServer.init(allocator, config);
    defer server.deinit();

    try server.run();
}

fn printUsage() void {
    const usage =
        \\打洞信令服务器
        \\
        \\用法: punch_server [选项]
        \\
        \\选项:
        \\  -p, --port <端口>    监听端口 (默认: 7891)
        \\  -h, --help          显示帮助信息
        \\
    ;
    std.debug.print("{s}", .{usage});
}

test "ServerConfig defaults" {
    const config = ServerConfig{};
    try std.testing.expectEqual(@as(u16, 7891), config.listen_port);
    try std.testing.expectEqual(@as(usize, 1024), config.max_clients);
}

test "PunchServer init and deinit" {
    const test_allocator = std.testing.allocator;
    var server = PunchServer.init(test_allocator, .{});
    defer server.deinit();

    try std.testing.expect(!server.running);
    try std.testing.expectEqual(@as(usize, 0), server.getClientCount());
}
