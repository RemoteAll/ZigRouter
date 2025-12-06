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
    listen_port: u16 = 18021,
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

    /// TCP 监听 socket
    listen_socket: ?posix.socket_t = null,

    /// UDP 监听 socket (用于公网地址探测)
    udp_socket: ?posix.socket_t = null,

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

        // 创建 UDP socket (用于公网地址探测，类似 STUN)
        const udp_sock = try posix.socket(
            posix.AF.INET,
            posix.SOCK.DGRAM,
            posix.IPPROTO.UDP,
        );
        errdefer posix.close(udp_sock);

        // 设置 UDP socket 选项
        try net_utils.setReuseAddr(udp_sock, true);

        // Windows UDP bug 修复 - 防止 ICMP port unreachable 导致后续 recvfrom 失败
        net_utils.windowsUdpBugFix(udp_sock);

        // 绑定 UDP 到同一端口
        try posix.bind(udp_sock, &listen_addr.any, listen_addr.getOsSockLen());

        self.udp_socket = udp_sock;
        self.running = true;

        log.info("服务器已启动，监听地址: {s}:{d}", .{ self.config.listen_addr, self.config.listen_port });
        log.info("TCP 信令通道: 已启用", .{});
        log.info("UDP 地址探测: 已启用 (端口 {d})", .{self.config.listen_port});
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

        // 关闭 UDP socket
        if (self.udp_socket) |sock| {
            posix.close(sock);
            self.udp_socket = null;
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

        // 启动 UDP 处理线程
        if (self.udp_socket) |udp_sock| {
            const udp_thread = std.Thread.spawn(.{}, handleUdpThread, .{ self, udp_sock }) catch |e| {
                log.err("创建 UDP 处理线程失败: {any}", .{e});
                return e;
            };
            udp_thread.detach();
        }

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
            var client_addr_buf: [64]u8 = undefined;
            const client_addr_str = ClientInfo.formatAddress(client_ep, &client_addr_buf);
            log.info("新 TCP 连接: {s}", .{client_addr_str});

            // 在新线程中处理客户端
            const thread = std.Thread.spawn(.{}, handleClientThread, .{ self, client_sock, client_ep }) catch |e| {
                log.err("创建客户端处理线程失败: {any}", .{e});
                posix.close(client_sock);
                continue;
            };
            thread.detach();
        }
    }

    /// UDP 处理线程函数
    /// 用于公网地址探测（类似 STUN，但使用自定义协议）
    fn handleUdpThread(self: *Self, udp_sock: posix.socket_t) void {
        log.info("UDP 地址探测服务已启动", .{});

        var buf: [1024]u8 = undefined;
        var src_addr: posix.sockaddr = undefined;
        var src_len: posix.socklen_t = @sizeOf(posix.sockaddr);

        while (self.running) {
            // 接收 UDP 数据
            const recv_result = posix.recvfrom(udp_sock, &buf, 0, &src_addr, &src_len);
            const recv_len = recv_result catch |e| {
                if (e == error.WouldBlock) {
                    std.Thread.sleep(10 * std.time.ns_per_ms);
                    continue;
                }
                log.err("UDP 接收错误: {any}", .{e});
                continue;
            };

            if (recv_len == 0) {
                continue;
            }

            // 检查消息类型（第一个字节为 0 表示地址探测请求）
            if (buf[0] != 0) {
                continue;
            }

            const client_ep = net.Address{ .any = src_addr };

            // 记录调试信息 - 使用 info 级别确保可见
            var addr_buf: [64]u8 = undefined;
            const addr_str = ClientInfo.formatAddress(client_ep, &addr_buf);
            log.info("收到 UDP 地址探测请求，来源: {s}", .{addr_str});

            // 构建响应：返回客户端的公网地址
            var response: [128]u8 = undefined;
            const resp_len = self.buildExternalAddrResponse(&response, client_ep);

            // 发送响应
            _ = posix.sendto(udp_sock, response[0..resp_len], 0, &src_addr, src_len) catch |e| {
                log.err("UDP 发送响应错误: {any}", .{e});
                continue;
            };

            log.info("已发送公网地址响应给: {s}, 响应长度: {d} 字节", .{ addr_str, resp_len });
        }

        log.info("UDP 地址探测服务已停止", .{});
    }

    /// 构建公网地址响应
    /// 格式: [AddressFamily(1)] [IP(4或16)] [Port(2)] [随机填充]
    /// 所有字节与 0xFF 异或以防止网关修改
    fn buildExternalAddrResponse(self: *Self, buffer: []u8, client_ep: net.Address) usize {
        _ = self;

        var offset: usize = 0;

        // AddressFamily (直接使用数值)
        buffer[offset] = @truncate(client_ep.any.family);
        offset += 1;

        // IP 地址
        const ip_len: usize = switch (client_ep.any.family) {
            posix.AF.INET => blk: {
                const addr_bytes = @as(*const [4]u8, @ptrCast(&client_ep.in.sa.addr));
                @memcpy(buffer[offset .. offset + 4], addr_bytes);
                break :blk 4;
            },
            posix.AF.INET6 => blk: {
                @memcpy(buffer[offset .. offset + 16], &client_ep.in6.sa.addr);
                break :blk 16;
            },
            else => 0,
        };
        offset += ip_len;

        // Port (大端序)
        const port = switch (client_ep.any.family) {
            posix.AF.INET => client_ep.in.sa.port,
            posix.AF.INET6 => client_ep.in6.sa.port,
            else => 0,
        };
        buffer[offset] = @truncate(port >> 8);
        buffer[offset + 1] = @truncate(port & 0xFF);
        offset += 2;

        // 对前面的字节进行异或（防止网关修改）
        for (0..offset) |i| {
            buffer[i] = buffer[i] ^ 0xFF;
        }

        // 添加随机填充（16-32 字节）
        var rng = std.Random.DefaultPrng.init(@bitCast(std.time.timestamp()));
        const random = rng.random();
        const padding_len = random.intRangeAtMost(usize, 16, 32);
        for (0..padding_len) |i| {
            buffer[offset + i] = random.int(u8);
        }
        offset += padding_len;

        return offset;
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

        // 发送注册成功响应（使用新注册的客户信息）
        try self.sendRegisterResponseToClient(&client_info);

        // 广播新客户端上线通知给其他客户端
        self.broadcastPeerOnline(&client_info);

        // 进入消息处理循环
        self.handleClientMessagesWithTls(client_info.machine_id) catch |e| {
            // ConnectionClosed 是客户端主动断开，不算错误
            if (e != error.ConnectionClosed) {
                log.err("客户端消息处理错误: {any}", .{e});
            }
        };

        // 广播客户端下线通知
        self.broadcastPeerOffline(client_info.machine_id);

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
                .punch_begin => {
                    // 转发打洞开始消息到目标
                    try self.handlePunchBeginForward(client, msg_payload);
                },
                .get_wan_port => {
                    // 转发获取端口请求到目标
                    try self.handleGetWanPortForward(client, msg_payload);
                },
                .get_wan_port_response => {
                    // 转发端口响应到请求方
                    try self.handleGetWanPortResponseForward(client, msg_payload);
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
    /// 心跳响应包含服务器当前时间戳，用于客户端时间同步
    fn sendHeartbeatResponseToClient(self: *Self, client: *const ClientInfo) !void {
        _ = self;

        // 构建 payload：服务器当前时间戳（毫秒）
        var payload_buf: [8]u8 = undefined;
        const server_time = std.time.milliTimestamp();
        std.mem.writeInt(i64, &payload_buf, server_time, .big);

        const msg_header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .heartbeat_response,
            .data_length = 8, // 包含 8 字节时间戳
            .sequence = 0,
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try msg_header.serialize(&header_buf);

        // 合并 header 和 payload
        var send_buf: [protocol.MessageHeader.SIZE + 8]u8 = undefined;
        @memcpy(send_buf[0..protocol.MessageHeader.SIZE], &header_buf);
        @memcpy(send_buf[protocol.MessageHeader.SIZE..], &payload_buf);

        try client.sendData(&send_buf);
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

        // 检测是否在同一局域网（公网地址相同）
        const same_lan = self.isSameLan(from_client, &target_client);
        if (same_lan) {
            var from_addr_buf: [64]u8 = undefined;
            var target_addr_buf: [64]u8 = undefined;
            log.info("╔══════════════════════════════════════════════════════════════╗", .{});
            log.info("║          检测到双方在同一局域网                              ║", .{});
            log.info("╠══════════════════════════════════════════════════════════════╣", .{});
            log.info("║ 发起方本地地址: {s}", .{ClientInfo.formatAddress(from_client.local_addr, &from_addr_buf)});
            log.info("║ 目标方本地地址: {s}", .{ClientInfo.formatAddress(target_client.local_addr, &target_addr_buf)});
            log.info("║ 将使用内网直连模式，跳过NAT打洞                              ║", .{});
            log.info("╚══════════════════════════════════════════════════════════════╝", .{});
        }

        // 检查 NAT 类型兼容性
        const can_p2p = from_client.nat_type.canP2P(target_client.nat_type);
        if (!can_p2p and request.transport != .tcp_port_map and request.transport != .udp_port_map and !same_lan) {
            log.warn("NAT 类型不兼容，可能无法打洞成功", .{});
            log.warn("  发起方 NAT: {s}", .{from_client.nat_type.description()});
            log.warn("  目标方 NAT: {s}", .{target_client.nat_type.description()});
        }

        // 向目标客户端发送打洞开始通知
        self.sendPunchBeginToClient(&target_client, from_client, &request, same_lan) catch |e| {
            log.err("向目标客户端发送打洞通知失败: {any}", .{e});
            try self.sendPunchResponseToClient(from_client, false, .unknown, null);
            self.stats.failed_punches += 1;
            return;
        };

        // 向发起方也发送打洞开始通知（包含目标信息）
        self.sendPunchBeginToInitiator(from_client, &target_client, &request, same_lan) catch |e| {
            log.err("向发起方发送打洞通知失败: {any}", .{e});
        };

        // 发送打洞成功响应给发起方
        try self.sendPunchResponseToClient(from_client, true, .success, null);

        self.stats.successful_punches += 1;
        if (same_lan) {
            log.info("已通知双方开始内网直连", .{});
        } else {
            log.info("已通知双方开始打洞", .{});
        }
    }

    /// 检测两个客户端是否在同一局域网
    /// 通过比较它们的公网地址（或连接地址）来判断
    fn isSameLan(self: *Self, client1: *const ClientInfo, client2: *const ClientInfo) bool {
        _ = self;

        // 获取两个客户端的公网地址
        const addr1 = client1.public_addr orelse client1.local_addr;
        const addr2 = client2.public_addr orelse client2.local_addr;

        // 添加调试日志
        var addr1_buf: [64]u8 = undefined;
        var addr2_buf: [64]u8 = undefined;
        log.debug("isSameLan 检测: 客户端1={s}, 客户端2={s}", .{
            ClientInfo.formatAddress(addr1, &addr1_buf),
            ClientInfo.formatAddress(addr2, &addr2_buf),
        });

        // 只比较 IP 地址，不比较端口
        if (addr1.any.family != addr2.any.family) {
            log.debug("isSameLan: 地址族不同，返回 false", .{});
            return false;
        }

        switch (addr1.any.family) {
            posix.AF.INET => {
                // IPv4: 比较 4 字节地址
                const same = addr1.in.sa.addr == addr2.in.sa.addr;
                log.debug("isSameLan: IPv4 比较结果={s}", .{if (same) "相同" else "不同"});
                return same;
            },
            posix.AF.INET6 => {
                // IPv6: 比较 16 字节地址
                const same = std.mem.eql(u8, &addr1.in6.sa.addr, &addr2.in6.sa.addr);
                log.debug("isSameLan: IPv6 比较结果={s}", .{if (same) "相同" else "不同"});
                return same;
            },
            else => {
                log.debug("isSameLan: 未知地址族，返回 false", .{});
                return false;
            },
        }
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

    /// 向目标客户端发送打洞开始通知
    fn sendPunchBeginToClient(self: *Self, target: *const ClientInfo, initiator: *const ClientInfo, request: *const protocol.PunchRequest, same_lan: bool) !void {
        _ = self;
        var payload_buf: [512]u8 = undefined;
        var payload_stream = std.io.fixedBufferStream(&payload_buf);
        const writer = payload_stream.writer();

        // 源机器 ID
        try writer.writeInt(u16, @intCast(initiator.machine_id.len), .big);
        try writer.writeAll(initiator.machine_id);

        // 源 NAT 类型
        try writer.writeByte(@intFromEnum(initiator.nat_type));

        // 传输方式
        try writer.writeByte(@intFromEnum(request.transport));

        // 方向 (对于目标客户端是反向)
        try writer.writeByte(@intFromEnum(types.TunnelDirection.reverse));

        // 事务 ID
        try writer.writeAll(&request.transaction_id);

        // 流 ID
        try writer.writeInt(u32, request.flow_id, .big);

        // SSL
        try writer.writeByte(if (request.ssl) 1 else 0);

        // 同局域网标志
        try writer.writeByte(if (same_lan) 1 else 0);

        // 发起方公网地址 - 使用正确的格式化函数
        var public_addr_buf: [64]u8 = undefined;
        const public_addr = if (initiator.public_addr) |addr|
            ClientInfo.formatAddress(addr, &public_addr_buf)
        else
            ClientInfo.formatAddress(initiator.local_addr, &public_addr_buf);
        try writer.writeInt(u16, @intCast(public_addr.len), .big);
        try writer.writeAll(public_addr);

        // 发起方本地地址
        var local_addr_buf: [64]u8 = undefined;
        const local_addr = ClientInfo.formatAddress(initiator.local_addr, &local_addr_buf);
        try writer.writeInt(u16, @intCast(local_addr.len), .big);
        try writer.writeAll(local_addr);

        const payload = payload_stream.getWritten();

        const msg_header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .punch_begin,
            .data_length = @intCast(payload.len),
            .sequence = 0,
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try msg_header.serialize(&header_buf);

        var send_buf: [768]u8 = undefined;
        @memcpy(send_buf[0..protocol.MessageHeader.SIZE], &header_buf);
        @memcpy(send_buf[protocol.MessageHeader.SIZE .. protocol.MessageHeader.SIZE + payload.len], payload);
        const total_len = protocol.MessageHeader.SIZE + payload.len;

        try target.sendData(send_buf[0..total_len]);

        log.info("已向目标 {s} 发送打洞开始通知，发起方: {s}，同局域网: {s}", .{ target.machine_id, initiator.machine_id, if (same_lan) "是" else "否" });
    }

    /// 向发起方发送打洞开始通知（包含目标信息）
    fn sendPunchBeginToInitiator(self: *Self, initiator: *const ClientInfo, target: *const ClientInfo, request: *const protocol.PunchRequest, same_lan: bool) !void {
        _ = self;
        var payload_buf: [512]u8 = undefined;
        var payload_stream = std.io.fixedBufferStream(&payload_buf);
        const writer = payload_stream.writer();

        // 目标机器 ID
        try writer.writeInt(u16, @intCast(target.machine_id.len), .big);
        try writer.writeAll(target.machine_id);

        // 目标 NAT 类型
        try writer.writeByte(@intFromEnum(target.nat_type));

        // 传输方式
        try writer.writeByte(@intFromEnum(request.transport));

        // 方向 (发起方是正向)
        try writer.writeByte(@intFromEnum(request.direction));

        // 事务 ID
        try writer.writeAll(&request.transaction_id);

        // 流 ID
        try writer.writeInt(u32, request.flow_id, .big);

        // SSL
        try writer.writeByte(if (request.ssl) 1 else 0);

        // 同局域网标志
        try writer.writeByte(if (same_lan) 1 else 0);

        // 目标公网地址 - 使用正确的格式化函数
        var public_addr_buf: [64]u8 = undefined;
        const public_addr = if (target.public_addr) |addr|
            ClientInfo.formatAddress(addr, &public_addr_buf)
        else
            ClientInfo.formatAddress(target.local_addr, &public_addr_buf);
        try writer.writeInt(u16, @intCast(public_addr.len), .big);
        try writer.writeAll(public_addr);

        // 目标本地地址
        var local_addr_buf: [64]u8 = undefined;
        const local_addr = ClientInfo.formatAddress(target.local_addr, &local_addr_buf);
        try writer.writeInt(u16, @intCast(local_addr.len), .big);
        try writer.writeAll(local_addr);

        const payload = payload_stream.getWritten();

        const msg_header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .punch_begin,
            .data_length = @intCast(payload.len),
            .sequence = 0,
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try msg_header.serialize(&header_buf);

        var send_buf: [768]u8 = undefined;
        @memcpy(send_buf[0..protocol.MessageHeader.SIZE], &header_buf);
        @memcpy(send_buf[protocol.MessageHeader.SIZE .. protocol.MessageHeader.SIZE + payload.len], payload);
        const total_len = protocol.MessageHeader.SIZE + payload.len;

        try initiator.sendData(send_buf[0..total_len]);

        log.info("已向发起方 {s} 发送打洞开始通知，目标: {s}", .{ initiator.machine_id, target.machine_id });
    }

    /// 处理打洞开始消息转发
    /// 客户端发送的 punch_begin 包含双方端口信息，服务器转发给目标并交换 Local/Remote
    fn handlePunchBeginForward(self: *Self, from_client: *const ClientInfo, payload: []const u8) !void {
        if (payload.len < 2) return;

        // 解析目标机器 ID
        const target_id_len = std.mem.readInt(u16, payload[0..2], .big);
        if (payload.len < 2 + target_id_len) return;
        const target_id = payload[2 .. 2 + target_id_len];

        log.info("转发打洞开始消息: {s} -> {s}", .{ from_client.machine_id, target_id });

        // 查找目标客户端
        self.clients_mutex.lock();
        const target = self.clients.get(target_id);
        self.clients_mutex.unlock();

        if (target == null) {
            log.warn("目标客户端不在线: {s}", .{target_id});
            return;
        }

        const target_client = target.?;

        // 构建转发消息，需要交换源和目标的端口信息
        // 原始格式:
        //   target_id, source_nat, transport, direction, txn_id, flow_id, ssl, same_lan,
        //   my_public, my_local, remote_public, remote_local
        // 转发后（交换 my 和 remote）:
        //   source_id, source_nat, transport, direction(反向), txn_id, flow_id, ssl, same_lan,
        //   remote_public(原my), remote_local(原my), my_public(原remote), my_local(原remote)

        var forward_buf: [1024]u8 = undefined;
        var forward_stream = std.io.fixedBufferStream(&forward_buf);
        const writer = forward_stream.writer();

        // 将源 ID 替换为发起方 ID（目标需要知道谁发起的）
        try writer.writeInt(u16, @intCast(from_client.machine_id.len), .big);
        try writer.writeAll(from_client.machine_id);

        // 跳过原始的 target_id，复制其余内容
        var offset: usize = 2 + target_id_len;

        // source_nat (1 byte)
        if (offset >= payload.len) return;
        try writer.writeByte(payload[offset]);
        offset += 1;

        // transport (1 byte)
        if (offset >= payload.len) return;
        try writer.writeByte(payload[offset]);
        offset += 1;

        // direction (1 byte) - 反转方向
        if (offset >= payload.len) return;
        const orig_direction = payload[offset];
        const new_direction: u8 = if (orig_direction == @intFromEnum(types.TunnelDirection.forward))
            @intFromEnum(types.TunnelDirection.reverse)
        else
            @intFromEnum(types.TunnelDirection.forward);
        try writer.writeByte(new_direction);
        offset += 1;

        // txn_id (16 bytes)
        if (offset + 16 > payload.len) return;
        try writer.writeAll(payload[offset .. offset + 16]);
        offset += 16;

        // flow_id (4 bytes)
        if (offset + 4 > payload.len) return;
        try writer.writeAll(payload[offset .. offset + 4]);
        offset += 4;

        // ssl (1 byte)
        if (offset >= payload.len) return;
        try writer.writeByte(payload[offset]);
        offset += 1;

        // same_lan (1 byte)
        if (offset >= payload.len) return;
        try writer.writeByte(payload[offset]);
        offset += 1;

        // 解析并交换端点字符串
        // my_public
        if (offset + 2 > payload.len) return;
        const my_public_len = std.mem.readInt(u16, payload[offset..][0..2], .big);
        offset += 2;
        if (offset + my_public_len > payload.len) return;
        const my_public = payload[offset .. offset + my_public_len];
        offset += my_public_len;

        // my_local
        if (offset + 2 > payload.len) return;
        const my_local_len = std.mem.readInt(u16, payload[offset..][0..2], .big);
        offset += 2;
        if (offset + my_local_len > payload.len) return;
        const my_local = payload[offset .. offset + my_local_len];
        offset += my_local_len;

        // remote_public
        if (offset + 2 > payload.len) return;
        const remote_public_len = std.mem.readInt(u16, payload[offset..][0..2], .big);
        offset += 2;
        if (offset + remote_public_len > payload.len) return;
        const remote_public = payload[offset .. offset + remote_public_len];
        offset += remote_public_len;

        // remote_local
        if (offset + 2 > payload.len) return;
        const remote_local_len = std.mem.readInt(u16, payload[offset..][0..2], .big);
        offset += 2;
        if (offset + remote_local_len > payload.len) return;
        const remote_local = payload[offset .. offset + remote_local_len];

        // 交换写入：对于目标来说，发起方的端点是"对方的"
        // 写入发起方的端点作为目标的"对方端点"
        try writer.writeInt(u16, @intCast(my_public_len), .big);
        if (my_public_len > 0) try writer.writeAll(my_public);
        try writer.writeInt(u16, @intCast(my_local_len), .big);
        if (my_local_len > 0) try writer.writeAll(my_local);

        // 写入目标自己的端点（从消息中的 remote 字段，这是发起方之前获取的目标端口）
        try writer.writeInt(u16, @intCast(remote_public_len), .big);
        if (remote_public_len > 0) try writer.writeAll(remote_public);
        try writer.writeInt(u16, @intCast(remote_local_len), .big);
        if (remote_local_len > 0) try writer.writeAll(remote_local);

        const forward_payload = forward_stream.getWritten();

        // 发送转发消息
        const msg_header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .punch_begin,
            .data_length = @intCast(forward_payload.len),
            .sequence = 0,
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try msg_header.serialize(&header_buf);

        var send_buf: [1280]u8 = undefined;
        @memcpy(send_buf[0..protocol.MessageHeader.SIZE], &header_buf);
        @memcpy(send_buf[protocol.MessageHeader.SIZE .. protocol.MessageHeader.SIZE + forward_payload.len], forward_payload);
        const total_len = protocol.MessageHeader.SIZE + forward_payload.len;

        try target_client.sendData(send_buf[0..total_len]);

        log.info("已转发打洞开始消息到 {s}", .{target_id});
    }

    /// 处理获取端口请求转发
    /// A 请求 B 的端口，服务器转发给 B
    fn handleGetWanPortForward(self: *Self, from_client: *const ClientInfo, payload: []const u8) !void {
        if (payload.len < 2) return;

        // 解析目标机器 ID
        const target_id_len = std.mem.readInt(u16, payload[0..2], .big);
        if (payload.len < 2 + target_id_len) return;
        const target_id = payload[2 .. 2 + target_id_len];

        log.info("转发端口请求: {s} -> {s}", .{ from_client.machine_id, target_id });

        // 查找目标客户端
        self.clients_mutex.lock();
        const target = self.clients.get(target_id);
        self.clients_mutex.unlock();

        if (target == null) {
            log.warn("目标客户端不在线: {s}", .{target_id});
            return;
        }

        const target_client = target.?;

        // 构建转发消息：将请求者 ID 放入 payload
        var forward_buf: [256]u8 = undefined;
        var forward_stream = std.io.fixedBufferStream(&forward_buf);
        const writer = forward_stream.writer();

        // 请求者 ID
        try writer.writeInt(u16, @intCast(from_client.machine_id.len), .big);
        try writer.writeAll(from_client.machine_id);

        const forward_payload = forward_stream.getWritten();

        const msg_header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .get_wan_port,
            .data_length = @intCast(forward_payload.len),
            .sequence = 0,
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try msg_header.serialize(&header_buf);

        var send_buf: [512]u8 = undefined;
        @memcpy(send_buf[0..protocol.MessageHeader.SIZE], &header_buf);
        @memcpy(send_buf[protocol.MessageHeader.SIZE .. protocol.MessageHeader.SIZE + forward_payload.len], forward_payload);
        const total_len = protocol.MessageHeader.SIZE + forward_payload.len;

        try target_client.sendData(send_buf[0..total_len]);

        log.debug("已转发端口请求到 {s}", .{target_id});
    }

    /// 处理端口响应转发
    /// B 响应端口信息，服务器转发给 A
    fn handleGetWanPortResponseForward(self: *Self, from_client: *const ClientInfo, payload: []const u8) !void {
        if (payload.len < 2) return;

        // 解析目标机器 ID（响应的目标是原请求者）
        const target_id_len = std.mem.readInt(u16, payload[0..2], .big);
        if (payload.len < 2 + target_id_len) return;
        const target_id = payload[2 .. 2 + target_id_len];

        log.info("转发端口响应: {s} -> {s}", .{ from_client.machine_id, target_id });

        // 查找目标客户端（原请求者）
        self.clients_mutex.lock();
        const target = self.clients.get(target_id);
        self.clients_mutex.unlock();

        if (target == null) {
            log.warn("请求者不在线: {s}", .{target_id});
            return;
        }

        const target_client = target.?;

        // 构建转发消息：将响应者 ID 和端口信息发给请求者
        var forward_buf: [512]u8 = undefined;
        var forward_stream = std.io.fixedBufferStream(&forward_buf);
        const writer = forward_stream.writer();

        // 响应者 ID（原来的 from_client）
        try writer.writeInt(u16, @intCast(from_client.machine_id.len), .big);
        try writer.writeAll(from_client.machine_id);

        // 复制端口信息（跳过目标 ID）
        const remaining = payload[2 + target_id_len ..];
        try writer.writeAll(remaining);

        const forward_payload = forward_stream.getWritten();

        const msg_header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .get_wan_port_response,
            .data_length = @intCast(forward_payload.len),
            .sequence = 0,
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try msg_header.serialize(&header_buf);

        var send_buf: [768]u8 = undefined;
        @memcpy(send_buf[0..protocol.MessageHeader.SIZE], &header_buf);
        @memcpy(send_buf[protocol.MessageHeader.SIZE .. protocol.MessageHeader.SIZE + forward_payload.len], forward_payload);
        const total_len = protocol.MessageHeader.SIZE + forward_payload.len;

        try target_client.sendData(send_buf[0..total_len]);

        log.debug("已转发端口响应到 {s}", .{target_id});
    }

    /// 广播新客户端上线通知给其他在线客户端
    fn broadcastPeerOnline(self: *Self, new_client: *const ClientInfo) void {
        // 构建通知消息
        var payload_buf: [512]u8 = undefined;
        var payload_stream = std.io.fixedBufferStream(&payload_buf);
        const writer = payload_stream.writer();

        // 写入新客户端信息
        writer.writeInt(u16, @intCast(new_client.machine_id.len), .big) catch return;
        writer.writeAll(new_client.machine_id) catch return;
        writer.writeInt(u16, @intCast(new_client.machine_name.len), .big) catch return;
        writer.writeAll(new_client.machine_name) catch return;
        writer.writeByte(@intFromEnum(new_client.nat_type)) catch return;

        const payload = payload_stream.getWritten();

        const msg_header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .peer_online,
            .data_length = @intCast(payload.len),
            .sequence = 0,
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        msg_header.serialize(&header_buf) catch return;

        // 合并 header 和 payload
        var send_buf: [768]u8 = undefined;
        @memcpy(send_buf[0..protocol.MessageHeader.SIZE], &header_buf);
        @memcpy(send_buf[protocol.MessageHeader.SIZE .. protocol.MessageHeader.SIZE + payload.len], payload);
        const total_len = protocol.MessageHeader.SIZE + payload.len;

        // 广播给所有其他客户端
        self.clients_mutex.lock();
        defer self.clients_mutex.unlock();

        var iter = self.clients.iterator();
        while (iter.next()) |entry| {
            // 跳过新注册的客户端自己
            if (std.mem.eql(u8, entry.key_ptr.*, new_client.machine_id)) continue;

            const client = entry.value_ptr;
            client.sendData(send_buf[0..total_len]) catch |e| {
                log.debug("发送上线通知给 {s} 失败: {any}", .{ client.machine_id, e });
            };
        }

        log.info("已广播节点上线通知: {s}", .{new_client.machine_id});
    }

    /// 广播客户端下线通知给其他在线客户端
    fn broadcastPeerOffline(self: *Self, machine_id: []const u8) void {
        // 构建通知消息
        var payload_buf: [256]u8 = undefined;
        var payload_stream = std.io.fixedBufferStream(&payload_buf);
        const writer = payload_stream.writer();

        // 写入下线客户端 ID
        writer.writeInt(u16, @intCast(machine_id.len), .big) catch return;
        writer.writeAll(machine_id) catch return;

        const payload = payload_stream.getWritten();

        const msg_header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .peer_offline,
            .data_length = @intCast(payload.len),
            .sequence = 0,
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        msg_header.serialize(&header_buf) catch return;

        // 合并 header 和 payload
        var send_buf: [512]u8 = undefined;
        @memcpy(send_buf[0..protocol.MessageHeader.SIZE], &header_buf);
        @memcpy(send_buf[protocol.MessageHeader.SIZE .. protocol.MessageHeader.SIZE + payload.len], payload);
        const total_len = protocol.MessageHeader.SIZE + payload.len;

        // 广播给所有其他客户端
        self.clients_mutex.lock();
        defer self.clients_mutex.unlock();

        var iter = self.clients.iterator();
        while (iter.next()) |entry| {
            // 跳过下线的客户端自己
            if (std.mem.eql(u8, entry.key_ptr.*, machine_id)) continue;

            const client = entry.value_ptr;
            client.sendData(send_buf[0..total_len]) catch |e| {
                log.debug("发送下线通知给 {s} 失败: {any}", .{ client.machine_id, e });
            };
        }

        log.info("已广播节点下线通知: {s}", .{machine_id});
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
    /// 心跳响应包含服务器当前时间戳，用于客户端时间同步
    fn sendHeartbeatResponse(self: *Self, sock: posix.socket_t) !void {
        _ = self;

        // 构建 payload：服务器当前时间戳（毫秒）
        var payload_buf: [8]u8 = undefined;
        const server_time = std.time.milliTimestamp();
        std.mem.writeInt(i64, &payload_buf, server_time, .big);

        const msg_header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .heartbeat_response,
            .data_length = 8, // 包含 8 字节时间戳
            .sequence = 0,
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try msg_header.serialize(&header_buf);

        // 合并 header 和 payload
        var send_buf: [protocol.MessageHeader.SIZE + 8]u8 = undefined;
        @memcpy(send_buf[0..protocol.MessageHeader.SIZE], &header_buf);
        @memcpy(send_buf[protocol.MessageHeader.SIZE..], &payload_buf);

        _ = posix.send(sock, &send_buf, 0) catch {};
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
                config.listen_port = std.fmt.parseInt(u16, args[i + 1], 10) catch 18021;
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
        \\  -p, --port <端口>     监听端口 (默认: 18021)
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
    try std.testing.expectEqual(@as(u16, 18021), config.listen_port);
    try std.testing.expectEqual(@as(usize, 1024), config.max_clients);
}

test "PunchServer init and deinit" {
    const test_allocator = std.testing.allocator;
    var server = PunchServer.init(test_allocator, .{});
    defer server.deinit();

    try std.testing.expect(!server.running);
    try std.testing.expectEqual(@as(usize, 0), server.getClientCount());
}
