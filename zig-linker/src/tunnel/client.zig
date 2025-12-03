//! 打洞客户端
//! 负责连接信令服务器并发起/响应打洞请求
//! 参考 C# linker 项目的实现

const std = @import("std");
const net = std.net;
const posix = std.posix;
const types = @import("types.zig");
const log = @import("log.zig");
const net_utils = @import("net_utils.zig");
const protocol = @import("protocol.zig");
const stun = @import("stun.zig");
const transport_mod = @import("transport.zig");

/// 客户端配置
pub const ClientConfig = struct {
    /// 服务器地址
    server_addr: []const u8 = "127.0.0.1",
    /// 服务器端口
    server_port: u16 = 7891,
    /// 本机 ID
    machine_id: []const u8 = "",
    /// 本机名称
    machine_name: []const u8 = "",
    /// 心跳间隔 (秒)
    heartbeat_interval: u32 = 30,
    /// 端口映射端口 (0 表示不使用)
    port_map_wan: u16 = 0,
    /// STUN 服务器 (用于 NAT 检测)
    stun_server: []const u8 = "stun.l.google.com",
    /// STUN 端口
    stun_port: u16 = 19302,
    /// 自动检测 NAT 类型
    auto_detect_nat: bool = true,
};

/// 打洞结果
pub const PunchResult = struct {
    /// 是否成功
    success: bool,
    /// 连接
    connection: ?transport_mod.ITunnelConnection = null,
    /// 错误信息
    error_message: []const u8 = "",
    /// 耗时 (毫秒)
    duration_ms: u64 = 0,
};

/// 在线节点信息
pub const PeerListItem = struct {
    machine_id: []const u8,
    machine_name: []const u8,
    nat_type: types.NatType,
};

/// 打洞客户端
pub const PunchClient = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    config: ClientConfig,

    /// 连接到服务器的 socket
    server_socket: ?posix.socket_t = null,

    /// 本机 NAT 类型
    local_nat_type: types.NatType = .unknown,

    /// 本机公网地址
    public_addr: ?net.Address = null,

    /// 本机本地地址
    local_addr: ?net.Address = null,

    /// 是否已注册
    registered: bool = false,

    /// 分配的 ID
    assigned_id: []const u8 = "",

    /// 传输管理器
    transport_manager: transport_mod.TransportManager,

    /// 当前序列号
    sequence: u32 = 0,

    /// 打洞回调
    on_punch_request: ?*const fn (*Self, *const protocol.PunchBegin) void = null,

    pub fn init(allocator: std.mem.Allocator, config: ClientConfig) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .transport_manager = transport_mod.TransportManager.init(allocator, .{}),
        };
    }

    pub fn deinit(self: *Self) void {
        self.disconnect();
        self.transport_manager.deinit();
        if (self.assigned_id.len > 0) {
            self.allocator.free(self.assigned_id);
        }
    }

    /// 连接到信令服务器
    pub fn connect(self: *Self) !void {
        if (self.server_socket != null) {
            log.warn("已连接到服务器", .{});
            return;
        }

        log.info("========================================", .{});
        log.info("  打洞客户端启动中...", .{});
        log.info("========================================", .{});

        // 检测 NAT 类型
        if (self.config.auto_detect_nat) {
            try self.detectNatType();
        }

        // 连接服务器
        const server_addr = try net.Address.parseIp(self.config.server_addr, self.config.server_port);

        // 根据地址族创建 socket
        const family_value = server_addr.any.family;
        const sock = blk: {
            if (family_value == 2) {
                break :blk try posix.socket(posix.AF.INET, posix.SOCK.STREAM, posix.IPPROTO.TCP);
            } else if (family_value == 10 or family_value == 23) {
                break :blk try posix.socket(posix.AF.INET6, posix.SOCK.STREAM, posix.IPPROTO.TCP);
            } else {
                return error.UnsupportedAddressFamily;
            }
        };
        errdefer posix.close(sock);

        try posix.connect(sock, &server_addr.any, server_addr.getOsSockLen());

        self.server_socket = sock;

        // 获取本地地址
        var local_sockaddr: posix.sockaddr = undefined;
        var local_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        try posix.getsockname(sock, &local_sockaddr, &local_len);
        self.local_addr = .{ .any = local_sockaddr };

        log.info("已连接到服务器: {s}:{d}", .{ self.config.server_addr, self.config.server_port });
        log.info("本地地址: {any}", .{self.local_addr});

        // 发送注册消息
        try self.register();
    }

    /// 断开连接
    pub fn disconnect(self: *Self) void {
        if (self.server_socket) |sock| {
            posix.close(sock);
            self.server_socket = null;
        }
        self.registered = false;
    }

    /// 检测 NAT 类型
    fn detectNatType(self: *Self) !void {
        log.info("正在检测 NAT 类型...", .{});

        // 解析 STUN 服务器地址
        const server_addr = net.Address.parseIp4(self.config.stun_server, self.config.stun_port) catch {
            log.warn("无法解析 STUN 服务器地址，使用默认 NAT 类型", .{});
            self.local_nat_type = .unknown;
            return;
        };

        const local_addr = net.Address.initIp4(.{ 0, 0, 0, 0 }, 0);

        var stun_client = stun.StunClient.init(server_addr, local_addr, .{});
        defer stun_client.deinit();

        const result = stun_client.query() catch |e| {
            log.warn("NAT 检测失败: {any}，使用默认值", .{e});
            self.local_nat_type = .unknown;
            return;
        };

        self.local_nat_type = result.nat_type;
        self.public_addr = result.public_endpoint;

        log.logNatDetection(
            result.nat_type,
            result.local_endpoint orelse net.Address.initIp4(.{ 0, 0, 0, 0 }, 0),
            result.public_endpoint,
        );
    }

    /// 注册到服务器
    fn register(self: *Self) !void {
        const sock = self.server_socket orelse return error.NotConnected;

        // 构造注册消息
        const peer_info = protocol.PeerInfo{
            .machine_id = if (self.config.machine_id.len > 0) self.config.machine_id else self.generateMachineId(),
            .machine_name = if (self.config.machine_name.len > 0) self.config.machine_name else "zig-client",
            .nat_type = self.local_nat_type,
            .local_endpoint = self.local_addr orelse net.Address.initIp4(.{ 0, 0, 0, 0 }, 0),
            .public_endpoint = null,
            .supported_transports = &[_]types.TransportType{},
            .port_map_wan = self.config.port_map_wan,
            .port_map_lan = 0,
            .route_level = 8,
        };

        const payload = try peer_info.serialize(self.allocator);
        defer self.allocator.free(payload);

        const header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .register,
            .data_length = @intCast(payload.len),
            .sequence = self.nextSequence(),
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try header.serialize(&header_buf);

        _ = try posix.send(sock, &header_buf, 0);
        _ = try posix.send(sock, payload, 0);

        // 等待响应
        var recv_buf: [256]u8 = undefined;
        const recv_len = try posix.recv(sock, &recv_buf, 0);

        if (recv_len < protocol.MessageHeader.SIZE) {
            return error.ProtocolError;
        }

        const resp_header = protocol.MessageHeader.parse(recv_buf[0..protocol.MessageHeader.SIZE]) catch return error.ProtocolError;

        if (resp_header.msg_type != .register_response) {
            return error.ProtocolError;
        }

        const resp_payload = recv_buf[protocol.MessageHeader.SIZE..recv_len];
        if (resp_payload.len < 1) return error.ProtocolError;

        const success = resp_payload[0] == 1;
        if (!success) {
            log.err("注册失败", .{});
            return error.RegistrationFailed;
        }

        // 读取分配的 ID
        if (resp_payload.len >= 3) {
            const id_len = std.mem.readInt(u16, resp_payload[1..3], .big);
            if (resp_payload.len >= 3 + id_len) {
                self.assigned_id = try self.allocator.dupe(u8, resp_payload[3 .. 3 + id_len]);
            }
        }

        self.registered = true;

        log.info("========================================", .{});
        log.info("  注册成功!", .{});
        log.info("  分配 ID: {s}", .{self.assigned_id});
        log.info("  NAT 类型: {s}", .{self.local_nat_type.description()});
        if (self.public_addr) |pub_addr| {
            log.info("  公网地址: {any}", .{pub_addr});
        }
        log.info("========================================", .{});
    }

    /// 生成机器 ID
    fn generateMachineId(self: *Self) []const u8 {
        _ = self;
        // 简单生成一个基于时间戳的 ID
        const timestamp = std.time.timestamp();
        var buf: [32]u8 = undefined;
        const id = std.fmt.bufPrint(&buf, "zig-{d}", .{timestamp}) catch "zig-client";
        return id;
    }

    /// 获取下一个序列号
    fn nextSequence(self: *Self) u32 {
        self.sequence +%= 1;
        return self.sequence;
    }

    /// 获取在线节点列表
    pub fn listPeers(self: *Self, allocator: std.mem.Allocator) !std.ArrayList(PeerListItem) {
        const sock = self.server_socket orelse return error.NotConnected;
        if (!self.registered) return error.NotRegistered;

        // 发送列表请求
        const header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .register,
            .data_length = 0,
            .sequence = self.nextSequence(),
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try header.serialize(&header_buf);
        _ = try posix.send(sock, &header_buf, 0);

        // 接收响应
        var recv_buf: [4096]u8 = undefined;
        const recv_len = try posix.recv(sock, &recv_buf, 0);

        if (recv_len < protocol.MessageHeader.SIZE) {
            return error.ProtocolError;
        }

        const resp_header = protocol.MessageHeader.parse(recv_buf[0..protocol.MessageHeader.SIZE]) catch return error.ProtocolError;

        if (resp_header.msg_type != .list_peers_response) {
            return error.ProtocolError;
        }

        // 解析节点列表
        const list_payload = recv_buf[protocol.MessageHeader.SIZE..recv_len];
        if (list_payload.len < 2) return error.ProtocolError;

        const count = std.mem.readInt(u16, list_payload[0..2], .big);

        var list: std.ArrayList(PeerListItem) = .{};
        var offset: usize = 2;

        var i: u16 = 0;
        while (i < count) : (i += 1) {
            if (offset + 2 > list_payload.len) break;

            const id_len = std.mem.readInt(u16, list_payload[offset..][0..2], .big);
            offset += 2;

            if (offset + id_len > list_payload.len) break;
            const machine_id = try allocator.dupe(u8, list_payload[offset .. offset + id_len]);
            offset += id_len;

            if (offset + 2 > list_payload.len) break;
            const name_len = std.mem.readInt(u16, list_payload[offset..][0..2], .big);
            offset += 2;

            if (offset + name_len > list_payload.len) break;
            const machine_name = try allocator.dupe(u8, list_payload[offset .. offset + name_len]);
            offset += name_len;

            if (offset + 1 > list_payload.len) break;
            const nat_type: types.NatType = @enumFromInt(list_payload[offset]);
            offset += 1;

            try list.append(allocator, PeerListItem{
                .machine_id = machine_id,
                .machine_name = machine_name,
                .nat_type = nat_type,
            });
        }

        return list;
    }

    /// 请求打洞
    pub fn requestPunch(self: *Self, target_id: []const u8, transport_type: types.TransportType) !PunchResult {
        const sock = self.server_socket orelse return PunchResult{ .success = false, .error_message = "未连接到服务器" };
        if (!self.registered) return PunchResult{ .success = false, .error_message = "未注册" };

        const start_time = std.time.milliTimestamp();

        log.info("========================================", .{});
        log.info("  发起打洞请求", .{});
        log.info("  目标: {s}", .{target_id});
        log.info("  传输方式: {s}", .{transport_type.description()});
        log.info("========================================", .{});

        // 生成事务 ID 和流程 ID
        var transaction_id: [16]u8 = undefined;
        std.crypto.random.bytes(&transaction_id);
        const flow_id: u32 = @truncate(@as(u64, @intCast(std.time.timestamp())));

        // 发送打洞请求
        const request = protocol.PunchRequest{
            .flow_id = flow_id,
            .target_machine_id = target_id,
            .transport = transport_type,
            .direction = .forward,
            .transaction_id = transaction_id,
            .ssl = false,
        };

        const payload = try request.serialize(self.allocator);
        defer self.allocator.free(payload);
        const payload_len = payload.len;

        const header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .punch_request,
            .data_length = @intCast(payload_len),
            .sequence = self.nextSequence(),
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try header.serialize(&header_buf);

        _ = try posix.send(sock, &header_buf, 0);
        _ = try posix.send(sock, payload, 0);

        // 等待打洞开始通知
        var recv_buf: [4096]u8 = undefined;
        const recv_len = posix.recv(sock, &recv_buf, 0) catch {
            return PunchResult{
                .success = false,
                .error_message = "接收响应失败",
                .duration_ms = @intCast(std.time.milliTimestamp() - start_time),
            };
        };

        if (recv_len < protocol.MessageHeader.SIZE) {
            return PunchResult{ .success = false, .error_message = "响应消息过短" };
        }

        const resp_header = protocol.MessageHeader.parse(recv_buf[0..protocol.MessageHeader.SIZE]) catch {
            return PunchResult{ .success = false, .error_message = "解析响应头失败" };
        };

        if (resp_header.msg_type == .punch_response) {
            // 直接收到错误响应
            const resp_payload = recv_buf[protocol.MessageHeader.SIZE..recv_len];
            if (resp_payload.len >= 1 and resp_payload[0] == 0) {
                return PunchResult{ .success = false, .error_message = "服务器拒绝打洞请求" };
            }
        }

        if (resp_header.msg_type != .punch_begin) {
            return PunchResult{ .success = false, .error_message = "收到意外的消息类型" };
        }

        // 解析打洞开始通知
        const begin_payload = recv_buf[protocol.MessageHeader.SIZE..recv_len];
        const begin = protocol.PunchBegin.parse(begin_payload) orelse {
            return PunchResult{ .success = false, .error_message = "解析打洞开始通知失败" };
        };

        log.info("收到打洞开始通知", .{});
        log.info("  对方 ID: {s}", .{begin.source_machine_id});
        log.info("  对方 NAT: {s}", .{begin.source_nat_type.description()});
        log.info("  方向: {s}", .{begin.direction.description()});

        // 解析对方地址
        var remote_endpoints: [4]net.Address = undefined;
        var endpoint_count: usize = 0;

        var addr_offset = begin.getSize();
        while (addr_offset < begin_payload.len and endpoint_count < 4) {
            const addr_type = begin_payload[addr_offset];
            addr_offset += 1;

            if (addr_type == 4 and addr_offset + 6 <= begin_payload.len) {
                // IPv4
                var addr: [4]u8 = undefined;
                @memcpy(&addr, begin_payload[addr_offset .. addr_offset + 4]);
                addr_offset += 4;

                var port_bytes: [2]u8 = undefined;
                @memcpy(&port_bytes, begin_payload[addr_offset .. addr_offset + 2]);
                const port = std.mem.readInt(u16, &port_bytes, .big);
                addr_offset += 2;

                remote_endpoints[endpoint_count] = net.Address.initIp4(addr, port);
                endpoint_count += 1;

                log.info("  对方端点 {d}: {any}", .{ endpoint_count, remote_endpoints[endpoint_count - 1] });
            } else if (addr_type == 6 and addr_offset + 18 <= begin_payload.len) {
                // IPv6
                var addr: [16]u8 = undefined;
                @memcpy(&addr, begin_payload[addr_offset .. addr_offset + 16]);
                addr_offset += 16;

                var port_bytes: [2]u8 = undefined;
                @memcpy(&port_bytes, begin_payload[addr_offset .. addr_offset + 2]);
                const port = std.mem.readInt(u16, &port_bytes, .big);
                addr_offset += 2;

                remote_endpoints[endpoint_count] = net.Address.initIp6(addr, port, 0, 0);
                endpoint_count += 1;

                log.info("  对方端点 {d}: {any}", .{ endpoint_count, remote_endpoints[endpoint_count - 1] });
            } else {
                break;
            }
        }

        if (endpoint_count == 0) {
            return PunchResult{ .success = false, .error_message = "没有可用的对方端点" };
        }

        // 构造传输信息
        const transport_info = types.TunnelTransportInfo{
            .flow_id = begin.flow_id,
            .direction = begin.direction,
            .local = types.EndpointInfo{
                .machine_id = self.assigned_id,
                .machine_name = self.config.machine_name,
                .nat_type = self.local_nat_type,
                .local = self.local_addr orelse net.Address.initIp4(.{ 0, 0, 0, 0 }, 0),
                .remote = self.public_addr,
                .port_map_wan = self.config.port_map_wan,
                .route_level = 8,
            },
            .remote = types.EndpointInfo{
                .machine_id = begin.source_machine_id,
                .machine_name = "",
                .nat_type = begin.source_nat_type,
                .local = remote_endpoints[0],
                .remote = if (endpoint_count > 1) remote_endpoints[1] else null,
                .port_map_wan = 0,
                .route_level = 8,
            },
            .remote_endpoints = remote_endpoints[0..endpoint_count],
            .ssl = false,
        };

        // 执行打洞
        const connection = self.transport_manager.connect(transport_type, &transport_info) catch {
            return PunchResult{
                .success = false,
                .error_message = "打洞连接失败",
                .duration_ms = @intCast(std.time.milliTimestamp() - start_time),
                .connection = null,
            };
        };

        const duration = @as(u64, @intCast(std.time.milliTimestamp() - start_time));

        if (connection) |conn| {
            log.info("========================================", .{});
            log.info("  打洞成功!", .{});
            log.info("  耗时: {d} ms", .{duration});
            log.info("  远程端点: {any}", .{conn.info.remote_endpoint});
            log.info("========================================", .{});

            return PunchResult{
                .success = true,
                .connection = conn,
                .duration_ms = duration,
            };
        } else {
            log.info("打洞失败，耗时: {d} ms", .{duration});
            return PunchResult{
                .success = false,
                .error_message = "打洞未成功建立连接",
                .duration_ms = duration,
            };
        }
    }

    /// 处理来自服务器的打洞开始通知
    pub fn handlePunchBegin(self: *Self, begin: *const protocol.PunchBegin, remote_endpoints: []const net.Address) !PunchResult {
        const start_time = std.time.milliTimestamp();

        log.info("========================================", .{});
        log.info("  收到打洞请求", .{});
        log.info("  发起方: {s}", .{begin.source_machine_id});
        log.info("  发起方 NAT: {s}", .{begin.source_nat_type.description()});
        log.info("  传输方式: {s}", .{begin.transport_type.description()});
        log.info("========================================", .{});

        // 构造传输信息 (注意方向是反的)
        const transport_info = types.TunnelTransportInfo{
            .flow_id = begin.flow_id,
            .direction = if (begin.direction == .forward) .reverse else .forward,
            .local = types.EndpointInfo{
                .machine_id = self.assigned_id,
                .machine_name = self.config.machine_name,
                .nat_type = self.local_nat_type,
                .local = self.local_addr orelse net.Address.initIp4(.{ 0, 0, 0, 0 }, 0),
                .public = self.public_addr,
                .port_map_wan = self.config.port_map_wan,
                .route_level = 8,
            },
            .remote = types.EndpointInfo{
                .machine_id = begin.source_machine_id,
                .machine_name = "",
                .nat_type = begin.source_nat_type,
                .local = if (remote_endpoints.len > 0) remote_endpoints[0] else net.Address.initIp4(.{ 0, 0, 0, 0 }, 0),
                .public = if (remote_endpoints.len > 1) remote_endpoints[1] else null,
                .port_map_wan = 0,
                .route_level = 8,
            },
            .remote_endpoints = remote_endpoints,
            .ssl = false,
        };

        // 执行打洞
        const connection = self.transport_manager.connect(begin.transport_type, &transport_info) catch |e| {
            _ = e;
            return PunchResult{
                .success = false,
                .error_message = "打洞连接失败",
                .duration_ms = @intCast(std.time.milliTimestamp() - start_time),
                .connection = null,
            };
        };

        const duration = @as(u64, @intCast(std.time.milliTimestamp() - start_time));

        if (connection) |conn| {
            log.info("被动打洞成功! 耗时: {d} ms", .{duration});
            return PunchResult{
                .success = true,
                .connection = conn,
                .duration_ms = duration,
            };
        } else {
            return PunchResult{
                .success = false,
                .error_message = "被动打洞失败",
                .duration_ms = duration,
            };
        }
    }

    /// 发送心跳
    pub fn sendHeartbeat(self: *Self) !void {
        const sock = self.server_socket orelse return error.NotConnected;

        const header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .heartbeat,
            .data_length = 0,
            .sequence = self.nextSequence(),
        };

        var buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try header.serialize(&buf);
        _ = try posix.send(sock, &buf, 0);
    }

    /// 运行消息循环
    pub fn runLoop(self: *Self) !void {
        const sock = self.server_socket orelse return error.NotConnected;

        var recv_buf: [4096]u8 = undefined;
        var last_heartbeat = std.time.timestamp();

        while (true) {
            // 检查心跳
            const now = std.time.timestamp();
            if (now - last_heartbeat >= self.config.heartbeat_interval) {
                self.sendHeartbeat() catch {};
                last_heartbeat = now;
            }

            // 设置接收超时
            net_utils.setRecvTimeout(sock, 1000) catch {};

            const recv_len = posix.recv(sock, &recv_buf, 0) catch |e| {
                if (e == error.WouldBlock) continue;
                return e;
            };

            if (recv_len == 0) {
                log.warn("服务器断开连接", .{});
                return error.ConnectionClosed;
            }

            if (recv_len < protocol.MessageHeader.SIZE) continue;

            const header = protocol.MessageHeader.parse(recv_buf[0..protocol.MessageHeader.SIZE]) catch continue;

            switch (header.msg_type) {
                .heartbeat_response => {
                    // 心跳响应，忽略
                },
                .punch_begin => {
                    // 收到打洞开始通知
                    const loop_payload = recv_buf[protocol.MessageHeader.SIZE..recv_len];
                    const begin = protocol.PunchBegin.parse(loop_payload) orelse continue;

                    if (self.on_punch_request) |callback| {
                        callback(self, &begin);
                    }
                },
                else => {
                    log.debug("收到未处理的消息类型: {any}", .{header.msg_type});
                },
            }
        }
    }

    /// 获取本机 NAT 类型
    pub fn getNatType(self: *const Self) types.NatType {
        return self.local_nat_type;
    }

    /// 获取公网地址
    pub fn getPublicAddress(self: *const Self) ?net.Address {
        return self.public_addr;
    }

    /// 是否已连接
    pub fn isConnected(self: *const Self) bool {
        return self.server_socket != null and self.registered;
    }
};

/// 客户端入口函数
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 解析命令行参数
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var config = ClientConfig{};
    var target_id: ?[]const u8 = null;
    var transport_str: []const u8 = "udp";
    var list_only = false;

    // 简单参数解析
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-s") or std.mem.eql(u8, arg, "--server")) {
            if (i + 1 < args.len) {
                config.server_addr = args[i + 1];
                i += 1;
            }
        } else if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--port")) {
            if (i + 1 < args.len) {
                config.server_port = std.fmt.parseInt(u16, args[i + 1], 10) catch 7891;
                i += 1;
            }
        } else if (std.mem.eql(u8, arg, "-n") or std.mem.eql(u8, arg, "--name")) {
            if (i + 1 < args.len) {
                config.machine_name = args[i + 1];
                i += 1;
            }
        } else if (std.mem.eql(u8, arg, "-t") or std.mem.eql(u8, arg, "--target")) {
            if (i + 1 < args.len) {
                target_id = args[i + 1];
                i += 1;
            }
        } else if (std.mem.eql(u8, arg, "-m") or std.mem.eql(u8, arg, "--method")) {
            if (i + 1 < args.len) {
                transport_str = args[i + 1];
                i += 1;
            }
        } else if (std.mem.eql(u8, arg, "-l") or std.mem.eql(u8, arg, "--list")) {
            list_only = true;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printUsage();
            return;
        }
    }

    // 解析传输方式
    const transport_type = parseTransportType(transport_str);

    var client = PunchClient.init(allocator, config);
    defer client.deinit();

    try client.connect();

    if (list_only) {
        // 只列出在线节点
        var peers = try client.listPeers(allocator);
        defer {
            for (peers.items) |peer| {
                allocator.free(peer.machine_id);
                allocator.free(peer.machine_name);
            }
            peers.deinit(allocator);
        }

        log.info("在线节点列表:", .{});
        log.info("========================================", .{});
        for (peers.items, 0..) |peer, idx| {
            log.info("  {d}. ID: {s}", .{ idx + 1, peer.machine_id });
            log.info("     名称: {s}", .{peer.machine_name});
            log.info("     NAT: {s}", .{peer.nat_type.description()});
        }
        if (peers.items.len == 0) {
            log.info("  (无其他在线节点)", .{});
        }
        log.info("========================================", .{});
    } else if (target_id) |tid| {
        // 发起打洞
        const result = try client.requestPunch(tid, transport_type);

        if (result.success) {
            log.info("打洞成功! 可以开始通信", .{});

            // 示例：发送测试消息
            if (result.connection) |*conn| {
                var connection = conn.*;
                _ = connection.send("Hello from Zig!") catch {};
                connection.close();
            }
        } else {
            log.err("打洞失败: {s}", .{result.error_message});
        }
    } else {
        // 等待其他节点连接
        log.info("等待打洞请求...", .{});
        try client.runLoop();
    }
}

fn parseTransportType(str: []const u8) types.TransportType {
    if (std.mem.eql(u8, str, "udp")) return .udp;
    if (std.mem.eql(u8, str, "tcp_p2p_nat") or std.mem.eql(u8, str, "tcp-p2p")) return .tcp_p2p_nat;
    if (std.mem.eql(u8, str, "tcp_nutssb") or std.mem.eql(u8, str, "tcp-ttl")) return .tcp_nutssb;
    if (std.mem.eql(u8, str, "udp_port_map") or std.mem.eql(u8, str, "udp-map")) return .udp_port_map;
    if (std.mem.eql(u8, str, "tcp_port_map") or std.mem.eql(u8, str, "tcp-map")) return .tcp_port_map;
    if (std.mem.eql(u8, str, "msquic") or std.mem.eql(u8, str, "quic")) return .msquic;
    return .udp;
}

fn printUsage() void {
    const usage =
        \\打洞客户端
        \\
        \\用法: client [选项]
        \\
        \\选项:
        \\  -s, --server <地址>   服务器地址 (默认: 127.0.0.1)
        \\  -p, --port <端口>     服务器端口 (默认: 7891)
        \\  -n, --name <名称>     本机名称
        \\  -t, --target <ID>     目标节点 ID (发起打洞)
        \\  -m, --method <方式>   传输方式:
        \\                          udp       - UDP 打洞 (默认)
        \\                          tcp-p2p   - TCP 同时打开
        \\                          tcp-ttl   - TCP 低 TTL
        \\                          udp-map   - UDP 端口映射
        \\                          tcp-map   - TCP 端口映射
        \\                          quic      - MsQuic
        \\  -l, --list            列出在线节点
        \\  -h, --help            显示帮助信息
        \\
        \\示例:
        \\  # 连接服务器并等待连接
        \\  client -s 192.168.1.100 -n "我的电脑"
        \\
        \\  # 列出在线节点
        \\  client -s 192.168.1.100 -l
        \\
        \\  # 向指定节点发起 UDP 打洞
        \\  client -s 192.168.1.100 -t node123 -m udp
        \\
    ;
    std.debug.print("{s}", .{usage});
}

test "ClientConfig defaults" {
    const config = ClientConfig{};
    try std.testing.expectEqual(@as(u16, 7891), config.server_port);
    try std.testing.expect(config.auto_detect_nat);
}

test "PunchClient init and deinit" {
    const allocator = std.testing.allocator;
    var client = PunchClient.init(allocator, .{});
    defer client.deinit();

    try std.testing.expect(!client.isConnected());
    try std.testing.expectEqual(types.NatType.unknown, client.getNatType());
}

test "parseTransportType" {
    try std.testing.expectEqual(types.TransportType.udp, parseTransportType("udp"));
    try std.testing.expectEqual(types.TransportType.tcp_p2p_nat, parseTransportType("tcp-p2p"));
    try std.testing.expectEqual(types.TransportType.tcp_nutssb, parseTransportType("tcp-ttl"));
    try std.testing.expectEqual(types.TransportType.udp, parseTransportType("unknown"));
}
