//! 打洞信令服务器
//! 负责协调客户端之间的打洞过程
//! 参考 C# linker 项目的实现

const std = @import("std");
const net = std.net;
const posix = std.posix;
const zzig = @import("zzig");
const types = @import("types.zig");
const log = @import("log.zig");
const net_utils = @import("net_utils.zig");
const protocol = @import("protocol.zig");
const stun = @import("stun.zig");
const tls = @import("tls.zig");

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
    /// TLS 连接 (堆分配，需要手动释放)
    tls_conn: ?*tls.TlsConnection = null,
    /// 是否使用 TLS
    use_tls: bool = false,
    /// 连接时间
    connected_at: i64,
    /// 最后活动时间
    last_active: i64,
    /// 端口映射端口
    port_map_wan: u16 = 0,
    /// 路由级别
    route_level: u8 = 8,

    /// 发送数据（自动处理 TLS）
    pub fn sendData(self: *const ClientInfo, data: []const u8) !void {
        if (self.use_tls and self.tls_conn != null) {
            _ = try self.tls_conn.?.send(data);
        } else {
            _ = try posix.send(self.socket, data, 0);
        }
    }

    /// 接收数据（自动处理 TLS）
    pub fn recvData(self: *const ClientInfo, buffer: []u8) !usize {
        if (self.use_tls and self.tls_conn != null) {
            return try self.tls_conn.?.recv(buffer);
        } else {
            return try posix.recv(self.socket, buffer, 0);
        }
    }

    /// 格式化地址为字符串
    pub fn formatAddress(addr: net.Address, buf: []u8) []const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const writer = fbs.writer();

        switch (addr.any.family) {
            posix.AF.INET => {
                const bytes = @as(*const [4]u8, @ptrCast(&addr.in.sa.addr));
                writer.print("{d}.{d}.{d}.{d}:{d}", .{
                    bytes[0],                                  bytes[1], bytes[2], bytes[3],
                    std.mem.bigToNative(u16, addr.in.sa.port),
                }) catch return "(error)";
            },
            posix.AF.INET6 => {
                writer.print("[IPv6]:{d}", .{
                    std.mem.bigToNative(u16, addr.in6.sa.port),
                }) catch return "(error)";
            },
            else => {
                return "(unknown)";
            },
        }
        return fbs.getWritten();
    }
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
    /// 是否启用 TLS
    tls_enabled: bool = true,
    /// 证书文件路径
    cert_file: []const u8 = "server.crt",
    /// 私钥文件路径
    key_file: []const u8 = "server.key",
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

    /// 客户端列表锁（多线程访问保护）
    clients_mutex: std.Thread.Mutex = .{},

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

        if (self.config.tls_enabled) {
            log.info("  TLS 加密: 已启用", .{});
        } else {
            log.warn("  TLS 加密: 已禁用 (不建议在公网使用)", .{});
        }

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

        // 关闭所有客户端连接，清理 TLS 资源（加锁）
        self.clients_mutex.lock();
        var iter = self.clients.iterator();
        while (iter.next()) |entry| {
            const client = entry.value_ptr;
            // 释放 TLS 连接内存
            if (client.tls_conn) |conn_ptr| {
                self.allocator.destroy(conn_ptr);
            }
            // 关闭 socket
            posix.close(client.socket);
            // 释放分配的字符串
            self.allocator.free(client.machine_id);
            self.allocator.free(client.machine_name);
        }
        self.clients.clearAndFree();
        self.clients_mutex.unlock();

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

            // 在新线程中处理客户端
            const thread = std.Thread.spawn(.{}, handleClientThread, .{ self, client_sock, client_ep }) catch |e| {
                log.err("创建客户端处理线程失败: {any}", .{e});
                posix.close(client_sock);
                continue;
            };
            thread.detach();
        }
    }

    /// 客户端处理线程函数
    fn handleClientThread(self: *Self, sock: posix.socket_t, client_ep: net.Address) void {
        self.handleClient(sock, client_ep) catch |e| {
            log.err("处理客户端错误: {any}", .{e});
            posix.close(sock);
        };
    }

    /// 处理客户端连接
    fn handleClient(self: *Self, sock: posix.socket_t, client_ep: net.Address) !void {
        self.stats.total_connections += 1;

        // TLS 连接（堆分配，便于存储到 ClientInfo）
        var tls_conn_ptr: ?*tls.TlsConnection = null;
        defer {
            // 如果未成功注册，需要清理 TLS 连接
            // 成功注册后由 ClientInfo 管理
        }

        // 如果启用 TLS，先进行握手
        if (self.config.tls_enabled) {
            // 堆分配 TLS 连接
            const conn_ptr = try self.allocator.create(tls.TlsConnection);
            errdefer self.allocator.destroy(conn_ptr);

            conn_ptr.* = tls.TlsConnection.initServer(sock, .{
                .enabled = true,
                .cert_file = self.config.cert_file,
                .key_file = self.config.key_file,
            });

            conn_ptr.handshake() catch |e| {
                log.err("TLS 握手失败: {any}", .{e});
                self.allocator.destroy(conn_ptr);
                return;
            };

            tls_conn_ptr = conn_ptr;
            log.info("TLS 握手成功", .{});
        }

        // 创建临时 ClientInfo 用于接收数据
        var temp_client = ClientInfo{
            .machine_id = "",
            .machine_name = "",
            .local_addr = client_ep,
            .socket = sock,
            .tls_conn = tls_conn_ptr,
            .use_tls = self.config.tls_enabled,
            .connected_at = std.time.timestamp(),
            .last_active = std.time.timestamp(),
        };

        // 接收注册消息
        var buf: [4096]u8 = undefined;
        const recv_len = temp_client.recvData(&buf) catch |e| {
            log.err("接收注册消息失败: {any}", .{e});
            if (tls_conn_ptr) |ptr| self.allocator.destroy(ptr);
            return;
        };

        if (recv_len < protocol.MessageHeader.SIZE) {
            log.err("消息太短", .{});
            if (tls_conn_ptr) |ptr| self.allocator.destroy(ptr);
            return;
        }

        // 解析消息头
        const header = protocol.MessageHeader.parse(buf[0..protocol.MessageHeader.SIZE]) catch |e| {
            log.err("解析消息头错误: {any}", .{e});
            if (tls_conn_ptr) |ptr| self.allocator.destroy(ptr);
            return;
        };

        if (header.msg_type != .register) {
            log.err("第一条消息必须是注册消息，收到: {any}", .{header.msg_type});
            if (tls_conn_ptr) |ptr| self.allocator.destroy(ptr);
            return;
        }

        // 解析注册消息
        const payload = buf[protocol.MessageHeader.SIZE..recv_len];
        const peer_info = protocol.PeerInfo.parse(payload, self.allocator) catch |e| {
            log.err("解析注册消息失败: {any}", .{e});
            if (tls_conn_ptr) |ptr| self.allocator.destroy(ptr);
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
            .tls_conn = tls_conn_ptr,
            .use_tls = self.config.tls_enabled,
            .connected_at = std.time.timestamp(),
            .last_active = std.time.timestamp(),
            .port_map_wan = peer_info.port_map_wan,
            .route_level = peer_info.route_level,
        };

        // 存储客户端信息（加锁）
        {
            self.clients_mutex.lock();
            defer self.clients_mutex.unlock();
            try self.clients.put(client_info.machine_id, client_info);
        }

        log.info("", .{});
        log.info("╔══════════════════════════════════════════════════════════════╗", .{});
        log.info("║              客户端注册成功                                  ║", .{});
        log.info("╠══════════════════════════════════════════════════════════════╣", .{});
        log.info("║ ID:       {s}", .{client_info.machine_id});
        log.info("║ 名称:     {s}", .{client_info.machine_name});
        log.info("║ NAT类型:  {s}", .{client_info.nat_type.description()});

        var local_buf: [64]u8 = undefined;
        log.info("║ 本地地址: {s}", .{ClientInfo.formatAddress(client_info.local_addr, &local_buf)});

        if (client_info.public_addr) |pub_addr| {
            var pub_buf: [64]u8 = undefined;
            log.info("║ 公网地址: {s}", .{ClientInfo.formatAddress(pub_addr, &pub_buf)});
        }

        if (client_info.port_map_wan != 0) {
            log.info("║ 端口映射: {d}", .{client_info.port_map_wan});
        }
        log.info("║ 路由层级: {d}", .{client_info.route_level});
        log.info("╠══════════════════════════════════════════════════════════════╣", .{});
        log.info("║ 当前在线客户端数: {d}", .{self.getClientCount()});
        log.info("╚══════════════════════════════════════════════════════════════╝", .{});
        log.info("", .{});

        // 打印所有在线客户端列表
        self.printOnlineClients();

        // 发送注册成功响应（使用新注册的客户端信息）
        try self.sendRegisterResponseToClient(&client_info);

        // 进入消息处理循环
        self.handleClientMessagesWithTls(client_info.machine_id) catch |e| {
            log.err("客户端消息处理错误: {any}", .{e});
        };

        // 客户端断开，清理
        log.info("客户端断开: {s}", .{client_info.machine_id});
        self.cleanupClient(client_info.machine_id);
    }

    /// 清理客户端资源（包括 TLS 连接）
    fn cleanupClient(self: *Self, machine_id: []const u8) void {
        self.clients_mutex.lock();
        const maybe_entry = self.clients.fetchRemove(machine_id);
        self.clients_mutex.unlock();

        if (maybe_entry) |entry| {
            const client = entry.value;
            // 释放 TLS 连接内存
            if (client.tls_conn) |conn_ptr| {
                self.allocator.destroy(conn_ptr);
            }
            // 关闭 socket
            posix.close(client.socket);
            // 释放 ID 和名称字符串
            self.allocator.free(client.machine_id);
            self.allocator.free(client.machine_name);
        }
    }

    /// 发送注册响应给客户端（使用 TLS）
    fn sendRegisterResponseToClient(self: *Self, client: *const ClientInfo) !void {
        _ = self;
        // 构建 payload
        var payload_buf: [256]u8 = undefined;
        var payload_stream = std.io.fixedBufferStream(&payload_buf);
        const payload_writer = payload_stream.writer();

        try payload_writer.writeByte(1); // success = true
        try payload_writer.writeInt(u16, @intCast(client.machine_id.len), .big);
        try payload_writer.writeAll(client.machine_id);

        const payload = payload_stream.getWritten();

        const msg_header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .register_response,
            .data_length = @intCast(payload.len),
            .sequence = 0,
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try msg_header.serialize(&header_buf);

        // 合并 header 和 payload 到一个缓冲区后一次性发送（TLS 需要一次性发送）
        var send_buf: [512]u8 = undefined;
        @memcpy(send_buf[0..protocol.MessageHeader.SIZE], &header_buf);
        @memcpy(send_buf[protocol.MessageHeader.SIZE .. protocol.MessageHeader.SIZE + payload.len], payload);
        const total_len = protocol.MessageHeader.SIZE + payload.len;

        try client.sendData(send_buf[0..total_len]);

        log.debug("已发送注册响应给 {s}，TLS: {}, 长度: {}", .{ client.machine_id, client.use_tls, total_len });
    }

    /// 处理客户端消息（使用 TLS）
    fn handleClientMessagesWithTls(self: *Self, machine_id: []const u8) !void {
        var buf: [4096]u8 = undefined;

        while (self.running) {
            // 获取客户端信息（加锁）
            self.clients_mutex.lock();
            const client_ptr = self.clients.getPtr(machine_id);
            self.clients_mutex.unlock();

            const client = client_ptr orelse {
                return error.ClientNotFound;
            };

            const recv_len = client.recvData(&buf) catch |e| {
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

            // 更新活动时间（加锁）
            self.clients_mutex.lock();
            if (self.clients.getPtr(machine_id)) |ptr| {
                ptr.last_active = std.time.timestamp();
            }
            self.clients_mutex.unlock();

            // 解析消息
            const header = protocol.MessageHeader.parse(buf[0..protocol.MessageHeader.SIZE]) catch continue;
            const msg_payload = buf[protocol.MessageHeader.SIZE..recv_len];

            switch (header.msg_type) {
                .heartbeat => {
                    try self.sendHeartbeatResponseToClient(client);
                },
                .punch_request => {
                    try self.handlePunchRequestWithTls(client, msg_payload);
                },
                .list_peers => {
                    try self.sendPeerListToClient(client);
                },
                else => {
                    log.debug("未知消息类型: {any}", .{header.msg_type});
                },
            }
        }
    }

    /// 发送心跳响应（使用 TLS）
    fn sendHeartbeatResponseToClient(self: *Self, client: *const ClientInfo) !void {
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
        try client.sendData(&buf);
    }

    /// 处理打洞请求（使用 TLS）
    fn handlePunchRequestWithTls(self: *Self, from_client: *const ClientInfo, payload: []const u8) !void {
        self.stats.total_punch_requests += 1;

        const request = protocol.PunchRequest.parse(payload) orelse {
            log.err("解析打洞请求失败", .{});
            return;
        };

        log.info("========================================", .{});
        log.info("  收到打洞请求", .{});
        log.info("  发起方: {s}", .{from_client.machine_id});
        log.info("  目标方: {s}", .{request.target_machine_id});
        log.info("  传输方式: {s}", .{request.transport.description()});
        log.info("========================================", .{});

        // 查找目标客户端（加锁）
        self.clients_mutex.lock();
        const target = self.clients.get(request.target_machine_id);
        self.clients_mutex.unlock();

        if (target == null) {
            log.err("目标客户端不在线: {s}", .{request.target_machine_id});
            try self.sendPunchResponseToClient(from_client, false, .peer_not_found, null);
            self.stats.failed_punches += 1;
            return;
        }

        const target_client = target.?;

        // 检查 NAT 类型兼容性
        const can_p2p = from_client.nat_type.canP2P(target_client.nat_type);
        if (!can_p2p and request.transport != .tcp_port_map and request.transport != .udp_port_map) {
            log.warn("NAT 类型不兼容，可能无法打洞成功", .{});
            log.warn("  发起方 NAT: {s}", .{from_client.nat_type.description()});
            log.warn("  目标方 NAT: {s}", .{target_client.nat_type.description()});
        }

        // 发送打洞成功响应
        try self.sendPunchResponseToClient(from_client, true, .success, null);

        log.info("已通知双方开始打洞", .{});
    }

    /// 发送打洞响应（使用 TLS）
    fn sendPunchResponseToClient(self: *Self, client: *const ClientInfo, success: bool, error_code: protocol.ErrorCode, connection_info: ?[]const u8) !void {
        _ = self;
        var payload_buf: [256]u8 = undefined;
        var payload_stream = std.io.fixedBufferStream(&payload_buf);
        const writer = payload_stream.writer();

        try writer.writeByte(if (success) 1 else 0);
        try writer.writeInt(u16, @intFromEnum(error_code), .big);

        if (connection_info) |info| {
            try writer.writeAll(info);
        }

        const payload = payload_stream.getWritten();

        const msg_header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .punch_response,
            .data_length = @intCast(payload.len),
            .sequence = 0,
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try msg_header.serialize(&header_buf);

        // 合并 header 和 payload 后一次性发送
        var send_buf: [512]u8 = undefined;
        @memcpy(send_buf[0..protocol.MessageHeader.SIZE], &header_buf);
        @memcpy(send_buf[protocol.MessageHeader.SIZE .. protocol.MessageHeader.SIZE + payload.len], payload);
        const total_len = protocol.MessageHeader.SIZE + payload.len;

        try client.sendData(send_buf[0..total_len]);
    }

    /// 发送在线客户端列表（使用 TLS）
    fn sendPeerListToClient(self: *Self, client: *const ClientInfo) !void {
        var payload_buf: [4096]u8 = undefined;
        var payload_stream = std.io.fixedBufferStream(&payload_buf);
        const writer = payload_stream.writer();

        var count: u16 = 0;
        try writer.writeInt(u16, 0, .big); // 占位符

        // 迭代客户端列表（加锁）- 使用作用域限制锁的范围
        {
            self.clients_mutex.lock();
            defer self.clients_mutex.unlock();

            var iter = self.clients.iterator();
            while (iter.next()) |entry| {
                if (std.mem.eql(u8, entry.key_ptr.*, client.machine_id)) continue;

                const peer = entry.value_ptr;
                try writer.writeInt(u16, @intCast(peer.machine_id.len), .big);
                try writer.writeAll(peer.machine_id);
                try writer.writeInt(u16, @intCast(peer.machine_name.len), .big);
                try writer.writeAll(peer.machine_name);
                try writer.writeByte(@intFromEnum(peer.nat_type));
                count += 1;
            }
        }

        // 回写数量
        const payload = payload_stream.getWritten();
        const count_bytes = std.mem.toBytes(std.mem.nativeToBig(u16, count));
        var payload_mutable: [4096]u8 = undefined;
        @memcpy(payload_mutable[0..payload.len], payload);
        @memcpy(payload_mutable[0..2], &count_bytes);

        const msg_header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .list_peers_response,
            .data_length = @intCast(payload.len),
            .sequence = 0,
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try msg_header.serialize(&header_buf);

        // 合并 header 和 payload 后一次性发送
        var send_buf: [4352]u8 = undefined; // 4096 + 256
        @memcpy(send_buf[0..protocol.MessageHeader.SIZE], &header_buf);
        @memcpy(send_buf[protocol.MessageHeader.SIZE .. protocol.MessageHeader.SIZE + payload.len], payload_mutable[0..payload.len]);
        const total_len = protocol.MessageHeader.SIZE + payload.len;

        try client.sendData(send_buf[0..total_len]);
    }

    /// 处理客户端消息（旧版，未使用 TLS，保留以供参考）
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

            // 更新活动时间（加锁）
            {
                self.clients_mutex.lock();
                defer self.clients_mutex.unlock();
                if (self.clients.getPtr(machine_id)) |client| {
                    client.last_active = std.time.timestamp();
                }
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

        // 查找目标客户端（加锁）
        self.clients_mutex.lock();
        const target = self.clients.get(request.target_machine_id);
        const from_client_opt = self.clients.get(from_id);
        self.clients_mutex.unlock();

        if (target == null) {
            log.err("目标客户端不在线: {s}", .{request.target_machine_id});
            try self.sendPunchResponse(sock, false, .peer_not_found, null);
            self.stats.failed_punches += 1;
            return;
        }

        const target_client = target.?;
        const from_client = from_client_opt orelse {
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

        // 迭代客户端列表（加锁）- 使用作用域限制锁的范围
        {
            self.clients_mutex.lock();
            defer self.clients_mutex.unlock();

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
    pub fn getClientCount(self: *Self) usize {
        self.clients_mutex.lock();
        defer self.clients_mutex.unlock();
        return self.clients.count();
    }

    /// 打印所有在线客户端列表（便于手动连接）
    pub fn printOnlineClients(self: *Self) void {
        self.clients_mutex.lock();
        defer self.clients_mutex.unlock();

        const count = self.clients.count();
        if (count == 0) {
            log.info("当前无在线客户端", .{});
            return;
        }

        log.info("", .{});
        log.info("┌────────────────────────────────────────────────────────────────────────────────┐", .{});
        log.info("│                           在线客户端列表 ({d} 个)                               │", .{count});
        log.info("├────┬──────────────────┬──────────────────┬──────────────┬─────────────────────┤", .{});
        log.info("│ #  │ ID               │ 名称             │ NAT类型      │ 公网地址            │", .{});
        log.info("├────┼──────────────────┼──────────────────┼──────────────┼─────────────────────┤", .{});

        var iter = self.clients.iterator();
        var idx: u32 = 1;
        while (iter.next()) |entry| {
            const client = entry.value_ptr;

            // 格式化 ID（截断或填充到 16 字符）
            var id_buf: [16]u8 = undefined;
            @memset(&id_buf, ' ');
            const id_len = @min(client.machine_id.len, 16);
            @memcpy(id_buf[0..id_len], client.machine_id[0..id_len]);

            // 格式化名称（截断或填充到 16 字符）
            var name_buf: [16]u8 = undefined;
            @memset(&name_buf, ' ');
            const name_len = @min(client.machine_name.len, 16);
            @memcpy(name_buf[0..name_len], client.machine_name[0..name_len]);

            // 格式化 NAT 类型（截断或填充到 12 字符）
            const nat_desc = client.nat_type.description();
            var nat_buf: [12]u8 = undefined;
            @memset(&nat_buf, ' ');
            const nat_len = @min(nat_desc.len, 12);
            @memcpy(nat_buf[0..nat_len], nat_desc[0..nat_len]);

            // 格式化公网地址
            var addr_buf: [64]u8 = undefined;
            var addr_str: []const u8 = "(无)";
            if (client.public_addr) |pub_addr| {
                addr_str = ClientInfo.formatAddress(pub_addr, &addr_buf);
            }

            log.info("│ {d: >2} │ {s} │ {s} │ {s} │ {s: <19} │", .{
                idx,
                id_buf,
                name_buf,
                nat_buf,
                addr_str,
            });

            idx += 1;
        }

        log.info("└────┴──────────────────┴──────────────────┴──────────────┴─────────────────────┘", .{});
        log.info("", .{});
        log.info("提示: 客户端可使用以下命令连接指定节点:", .{});
        log.info("  punch_client -s <服务器地址> -t <目标ID> -m <打洞方式>", .{});
        log.info("  打洞方式: udp, udp-p2p, tcp-p2p, tcp-ttl, udp-map, tcp-map, quic", .{});
        log.info("", .{});
    }
};

/// 服务器入口函数
pub fn main() !void {
    // 初始化控制台，支持 UTF-8 中文显示
    zzig.Console.setup();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 解析命令行参数
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var config = ServerConfig{};
    var cmd_tls_enabled: ?bool = null;
    var cmd_cert_file: ?[]const u8 = null;
    var cmd_key_file: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--port")) {
            if (i + 1 < args.len) {
                config.listen_port = std.fmt.parseInt(u16, args[i + 1], 10) catch 7891;
                i += 1;
            }
        } else if (std.mem.eql(u8, arg, "--tls")) {
            cmd_tls_enabled = true;
        } else if (std.mem.eql(u8, arg, "--no-tls")) {
            cmd_tls_enabled = false;
        } else if (std.mem.eql(u8, arg, "--cert")) {
            if (i + 1 < args.len) {
                cmd_cert_file = args[i + 1];
                i += 1;
            }
        } else if (std.mem.eql(u8, arg, "--key")) {
            if (i + 1 < args.len) {
                cmd_key_file = args[i + 1];
                i += 1;
            }
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printUsage();
            return;
        }
    }

    // 应用命令行参数
    if (cmd_tls_enabled) |v| config.tls_enabled = v;
    if (cmd_cert_file) |v| config.cert_file = v;
    if (cmd_key_file) |v| config.key_file = v;

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
        \\  -p, --port <端口>     监听端口 (默认: 7891)
        \\
        \\TLS 选项:
        \\  --tls                 强制启用 TLS 加密 (默认已启用)
        \\  --no-tls              禁用 TLS 加密 (仅用于本地调试)
        \\  --cert <路径>         TLS 证书文件路径 (默认: server.crt)
        \\  --key <路径>          TLS 私钥文件路径 (默认: server.key)
        \\
        \\  -h, --help            显示帮助信息
        \\
        \\说明:
        \\  首次启动时，如果证书文件不存在，会自动生成自签名证书。
        \\  自签名证书仅用于测试，生产环境请使用正式的 TLS 证书。
        \\
        \\示例:
        \\  # 默认启动 (TLS 启用，自动生成证书)
        \\  punch_server
        \\
        \\  # 指定端口
        \\  punch_server -p 8891
        \\
        \\  # 使用指定证书
        \\  punch_server --cert /path/to/cert.pem --key /path/to/key.pem
        \\
        \\  # 本地调试禁用 TLS
        \\  punch_server --no-tls
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
