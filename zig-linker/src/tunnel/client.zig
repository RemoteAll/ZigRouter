//! 打洞客户端
//! 负责连接信令服务器并发起/响应打洞请求
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
const transport_mod = @import("transport.zig");
const config_mod = @import("config.zig");
const tls = @import("tls.zig");

/// 格式化地址为可读字符串
fn formatAddress(addr: net.Address, buf: []u8) []const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const writer = fbs.writer();

    switch (addr.any.family) {
        posix.AF.INET => {
            const bytes = @as(*const [4]u8, @ptrCast(&addr.in.sa.addr));
            writer.print("{d}.{d}.{d}.{d}:{d}", .{
                bytes[0],
                bytes[1],
                bytes[2],
                bytes[3],
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

/// 解析端点字符串为地址 (格式: ip:port 或 net.Address{...})
fn parseEndpointString(endpoint_str: []const u8) ?net.Address {
    // 尝试解析简单格式 "ip:port"
    if (std.mem.lastIndexOfScalar(u8, endpoint_str, ':')) |colon_idx| {
        const ip_str = endpoint_str[0..colon_idx];
        const port_str = endpoint_str[colon_idx + 1 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch return null;
        return net.Address.parseIp(ip_str, port) catch return null;
    }
    return null;
}

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
    /// 是否启用 TLS 加密
    tls_enabled: bool = true,
    /// 是否跳过服务器证书验证（用于自签名证书）
    tls_skip_verify: bool = false,
    /// 是否自动与新上线节点打洞
    auto_punch_on_peer_online: bool = false,
    /// 传输方式配置列表（打洞方式优先级）
    transports: []const config_mod.TransportConfig = &.{},
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

    /// TLS 连接
    tls_conn: ?tls.TlsConnection = null,

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

    /// 节点上线回调
    on_peer_online: ?*const fn (*Self, *const protocol.PeerOnline) void = null,

    /// 节点下线回调
    on_peer_offline: ?*const fn (*Self, *const protocol.PeerOffline) void = null,

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

        if (self.config.tls_enabled) {
            log.info("  TLS 加密: 已启用", .{});
        } else {
            log.warn("  TLS 加密: 已禁用 (不建议在公网使用)", .{});
        }

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

        // 如果启用 TLS，进行握手
        if (self.config.tls_enabled) {
            var conn = tls.TlsConnection.initClient(sock, .{
                .enabled = true,
                // skip_verify 取反为 verify_peer
                .verify_peer = !self.config.tls_skip_verify,
                .server_name = self.config.server_addr,
            });
            conn.handshake() catch |e| {
                log.err("TLS 握手失败: {any}", .{e});
                return e;
            };
            self.tls_conn = conn;
            log.info("TLS 握手成功，连接已加密", .{});
        }

        // 获取本地地址
        var local_sockaddr: posix.sockaddr = undefined;
        var local_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        try posix.getsockname(sock, &local_sockaddr, &local_len);
        self.local_addr = .{ .any = local_sockaddr };

        log.info("已连接到服务器: {s}:{d}", .{ self.config.server_addr, self.config.server_port });

        // 格式化本地地址
        if (self.local_addr) |addr| {
            var addr_buf: [64]u8 = undefined;
            const local_addr_str = formatAddress(addr, &addr_buf);
            log.info("本地地址: {s}", .{local_addr_str});
        }

        // 发送注册消息
        try self.register();
    }

    /// 断开连接
    pub fn disconnect(self: *Self) void {
        if (self.tls_conn) |*tc| {
            tc.close();
            self.tls_conn = null;
        } else if (self.server_socket) |sock| {
            posix.close(sock);
        }
        self.server_socket = null;
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

        // 合并 header 和 payload 为一次发送
        var send_buf: [4096]u8 = undefined;
        @memcpy(send_buf[0..protocol.MessageHeader.SIZE], &header_buf);
        @memcpy(send_buf[protocol.MessageHeader.SIZE .. protocol.MessageHeader.SIZE + payload.len], payload);
        const total_len = protocol.MessageHeader.SIZE + payload.len;

        // 发送数据（使用 TLS 或普通 socket）
        if (self.tls_conn) |*tc| {
            _ = try tc.send(send_buf[0..total_len]);
        } else {
            _ = try posix.send(sock, send_buf[0..total_len], 0);
        }

        // 等待响应
        var recv_buf: [256]u8 = undefined;
        const recv_len = if (self.tls_conn) |*tc| blk: {
            break :blk try tc.recv(&recv_buf);
        } else blk: {
            break :blk try posix.recv(sock, &recv_buf, 0);
        };

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
        if (self.config.tls_enabled) {
            log.info("  连接状态: TLS 加密", .{});
        }
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
        if (self.server_socket == null) return error.NotConnected;

        const header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .heartbeat,
            .data_length = 0,
            .sequence = self.nextSequence(),
        };

        var buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try header.serialize(&buf);

        // 使用 TLS 或普通 socket 发送
        if (self.tls_conn) |*tc| {
            _ = try tc.send(&buf);
        } else {
            _ = try posix.send(self.server_socket.?, &buf, 0);
        }
    }

    /// 发送打洞请求
    pub fn sendPunchRequest(self: *Self, target_machine_id: []const u8) !void {
        if (self.server_socket == null) return error.NotConnected;

        // 构建打洞请求 payload
        var payload_buf: [512]u8 = undefined;
        var payload_stream = std.io.fixedBufferStream(&payload_buf);
        const writer = payload_stream.writer();

        // 目标机器 ID (2 bytes length + data)
        try writer.writeInt(u16, @intCast(target_machine_id.len), .big);
        try writer.writeAll(target_machine_id);

        // 传输方式 (1 byte) - 默认使用 UDP
        try writer.writeByte(@intFromEnum(types.TransportType.udp));

        // 方向 (1 byte) - 正向
        try writer.writeByte(@intFromEnum(types.TunnelDirection.forward));

        // 事务 ID (16 bytes)
        const transaction_id = protocol.generateTransactionId();
        try writer.writeAll(&transaction_id);

        // 流 ID (4 bytes)
        try writer.writeInt(u32, 0, .big);

        // SSL (1 byte)
        try writer.writeByte(if (self.config.tls_enabled) 1 else 0);

        const payload = payload_stream.getWritten();

        const header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .punch_request,
            .data_length = @intCast(payload.len),
            .sequence = self.nextSequence(),
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try header.serialize(&header_buf);

        // 合并 header 和 payload
        var send_buf: [768]u8 = undefined;
        @memcpy(send_buf[0..protocol.MessageHeader.SIZE], &header_buf);
        @memcpy(send_buf[protocol.MessageHeader.SIZE .. protocol.MessageHeader.SIZE + payload.len], payload);
        const total_len = protocol.MessageHeader.SIZE + payload.len;

        // 使用 TLS 或普通 socket 发送
        if (self.tls_conn) |*tc| {
            _ = try tc.send(send_buf[0..total_len]);
        } else {
            _ = try posix.send(self.server_socket.?, send_buf[0..total_len], 0);
        }

        log.info("已发送打洞请求，目标: {s}", .{target_machine_id});
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

            // 使用 TLS 或普通 socket 接收
            const recv_len = if (self.tls_conn) |*tc| blk: {
                break :blk tc.recv(&recv_buf) catch |e| {
                    if (e == error.WouldBlock) continue;
                    // TLS 超时也视为 WouldBlock
                    if (e == error.ConnectionTimedOut) continue;
                    // 连接被重置
                    if (e == error.ConnectionResetByPeer) {
                        log.warn("连接被服务器重置", .{});
                        return error.ConnectionClosed;
                    }
                    return e;
                };
            } else blk: {
                break :blk posix.recv(sock, &recv_buf, 0) catch |e| {
                    if (e == error.WouldBlock) continue;
                    if (e == error.ConnectionTimedOut) continue;
                    if (e == error.ConnectionResetByPeer) {
                        log.warn("连接被服务器重置", .{});
                        return error.ConnectionClosed;
                    }
                    return e;
                };
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

                    // 显示详细的打洞请求信息和 NAT 分析
                    log.info("", .{});
                    log.info("╔══════════════════════════════════════════════════════════════╗", .{});
                    if (begin.same_lan) {
                        log.info("║              收到内网直连请求                                 ║", .{});
                    } else {
                        log.info("║              收到打洞请求                                     ║", .{});
                    }
                    log.info("╠══════════════════════════════════════════════════════════════╣", .{});
                    log.info("║ 对方节点 ID:   {s}", .{begin.source_machine_id});
                    log.info("║ 对方 NAT 类型: {s}", .{begin.source_nat_type.description()});
                    log.info("║ 本地 NAT 类型: {s}", .{self.local_nat_type.description()});
                    log.info("║ 打洞方向:      {s}", .{if (begin.direction == .forward) "正向 (我方主动)" else "反向 (我方被动)"});
                    log.info("║ 传输方式:      {s}", .{begin.transport.description()});
                    log.info("║ 需要 SSL:      {s}", .{if (begin.ssl) "是" else "否"});
                    log.info("║ 同一局域网:    {s}", .{if (begin.same_lan) "✓ 是" else "✗ 否"});
                    if (begin.public_endpoint.len > 0) {
                        log.info("║ 对方公网地址:  {s}", .{begin.public_endpoint});
                    }
                    if (begin.local_endpoint.len > 0) {
                        log.info("║ 对方本地地址:  {s}", .{begin.local_endpoint});
                    }
                    log.info("╠══════════════════════════════════════════════════════════════╣", .{});

                    // NAT 类型兼容性分析
                    if (begin.same_lan) {
                        log.info("║ 连接策略:     ✓ 同局域网，将使用内网地址直连", .{});
                    } else {
                        const can_p2p = self.local_nat_type.canP2P(begin.source_nat_type);
                        if (can_p2p) {
                            log.info("║ NAT 兼容性:    ✓ 可直接 P2P 打洞", .{});
                        } else {
                            log.info("║ NAT 兼容性:    ✗ 难以直接 P2P，需要中继或端口映射", .{});
                        }
                    }
                    log.info("╚══════════════════════════════════════════════════════════════╝", .{});

                    // 调用回调（如果有）
                    if (self.on_punch_request) |callback| {
                        callback(self, &begin);
                    }

                    // 执行实际打洞 - 使用配置的传输方式逐一尝试
                    if (self.config.transports.len > 0) {
                        log.info("", .{});
                        if (begin.same_lan) {
                            log.info("检测到同局域网，将优先尝试内网直连...", .{});
                        } else {
                            log.info("开始执行打洞流程，将按优先级尝试 {d} 种打洞方式...", .{self.config.transports.len});
                        }

                        const punch_result = self.executePunchWithPeerInfo(&begin) catch |e| {
                            log.err("打洞执行失败: {any}", .{e});
                            continue;
                        };

                        // 显示打洞结果
                        self.printPunchResult(&punch_result, &begin);
                    } else {
                        log.warn("未配置打洞方式，无法执行实际打洞", .{});
                    }
                },
                .peer_online => {
                    // 收到节点上线通知
                    const loop_payload = recv_buf[protocol.MessageHeader.SIZE..recv_len];
                    const peer_info = protocol.PeerOnline.parse(loop_payload) orelse continue;

                    log.info("", .{});
                    log.info("╔══════════════════════════════════════════════════════════════╗", .{});
                    log.info("║              新节点上线                                       ║", .{});
                    log.info("╠══════════════════════════════════════════════════════════════╣", .{});
                    log.info("║ ID:   {s}", .{peer_info.machine_id});
                    log.info("║ 名称: {s}", .{peer_info.machine_name});
                    log.info("║ NAT:  {s}", .{peer_info.nat_type.description()});
                    log.info("╚══════════════════════════════════════════════════════════════╝", .{});

                    // 调用回调
                    if (self.on_peer_online) |callback| {
                        callback(self, &peer_info);
                    }

                    // 如果启用了自动打洞，尝试与新节点建立连接
                    if (self.config.auto_punch_on_peer_online) {
                        log.info("自动打洞已启用，正在尝试与 {s} 打洞...", .{peer_info.machine_id});
                        self.sendPunchRequest(peer_info.machine_id) catch |e| {
                            log.err("发送打洞请求失败: {any}", .{e});
                        };
                    }
                },
                .peer_offline => {
                    // 收到节点下线通知
                    const loop_payload = recv_buf[protocol.MessageHeader.SIZE..recv_len];
                    const peer_info = protocol.PeerOffline.parse(loop_payload) orelse continue;

                    log.info("", .{});
                    log.info("┌──────────────────────────────────────────────────────────────┐", .{});
                    log.info("│ 节点下线: {s}", .{peer_info.machine_id});
                    log.info("└──────────────────────────────────────────────────────────────┘", .{});

                    // 调用回调
                    if (self.on_peer_offline) |callback| {
                        callback(self, &peer_info);
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

    /// 使用对方信息执行打洞 - 根据收到的 PunchBegin 信息执行打洞
    pub fn executePunchWithPeerInfo(self: *Self, begin: *const protocol.PunchBegin) !AutoPunchResult {
        var result = AutoPunchResult{
            .success = false,
            .tried_methods = 0,
            .successful_method = null,
            .connection = null,
            .total_duration_ms = 0,
            .results = undefined,
        };

        const start_time = std.time.milliTimestamp();

        log.info("", .{});
        log.info("╔══════════════════════════════════════════════════════════════╗", .{});
        log.info("║              开始打洞流程                                    ║", .{});
        log.info("╠══════════════════════════════════════════════════════════════╣", .{});
        log.info("║ 目标节点:   {s}", .{begin.source_machine_id});
        log.info("║ 目标 NAT:   {s}", .{begin.source_nat_type.description()});
        log.info("║ 本地 NAT:   {s}", .{self.local_nat_type.description()});
        log.info("║ 打洞方向:   {s}", .{if (begin.direction == .forward) "正向" else "反向"});
        log.info("║ 待尝试方式: {d}", .{self.config.transports.len});
        log.info("╚══════════════════════════════════════════════════════════════╝", .{});
        log.info("", .{});

        var method_idx: usize = 0;
        for (self.config.transports) |transport_config| {
            if (!transport_config.enabled) {
                log.debug("跳过已禁用的打洞方式: {s}", .{transport_config.name});
                continue;
            }

            const transport_type = config_mod.ClientConfiguration.getTransportType(transport_config.name) orelse {
                log.warn("未知的打洞方式: {s}", .{transport_config.name});
                continue;
            };

            if (method_idx >= result.results.len) break;

            result.tried_methods += 1;
            const method_start = std.time.milliTimestamp();

            log.info("┌──────────────────────────────────────────────────────────────┐", .{});
            log.info("│ [{d}/{d}] 尝试: {s}", .{ result.tried_methods, self.config.transports.len, transport_config.name });
            log.info("│ 优先级: {d}, 超时: {d}s, 重试: {d}次", .{
                transport_config.priority,
                transport_config.timeout_seconds,
                transport_config.retry_count,
            });
            log.info("└──────────────────────────────────────────────────────────────┘", .{});

            // 尝试打洞
            var retry: u8 = 0;
            var punch_success = false;
            var punch_connection: ?transport_mod.ITunnelConnection = null;
            var error_msg: []const u8 = "";

            while (retry <= transport_config.retry_count) : (retry += 1) {
                if (retry > 0) {
                    log.info("  重试第 {d}/{d} 次...", .{ retry, transport_config.retry_count });
                    std.Thread.sleep(500 * std.time.ns_per_ms);
                }

                // 执行具体的打洞方式
                const conn_result = self.tryPunchMethod(transport_type, begin, transport_config.timeout_seconds);

                if (conn_result.success) {
                    punch_success = true;
                    punch_connection = conn_result.connection;
                    error_msg = ""; // 成功时清空错误信息
                    log.info("  ✓ {s} 打洞成功!", .{transport_config.name});
                    break;
                } else {
                    error_msg = conn_result.error_message;
                    log.debug("  尝试 {s} 失败: {s}", .{ transport_config.name, error_msg });
                }
            }

            const method_duration = @as(u64, @intCast(std.time.milliTimestamp() - method_start));

            // 记录结果
            result.results[method_idx] = .{
                .transport_name = transport_config.name,
                .success = punch_success,
                .duration_ms = method_duration,
                .error_message = if (punch_success) "" else error_msg, // 成功时不保留错误信息
            };
            method_idx += 1;

            if (punch_success) {
                result.success = true;
                result.successful_method = transport_type;
                result.connection = punch_connection;
                break;
            } else {
                log.warn("  ✗ {s} 失败: {s} ({d}ms)", .{ transport_config.name, error_msg, method_duration });
            }
        }

        result.total_duration_ms = @intCast(std.time.milliTimestamp() - start_time);
        return result;
    }

    /// 尝试具体的打洞方式
    fn tryPunchMethod(self: *Self, transport_type: types.TransportType, begin: *const protocol.PunchBegin, timeout_seconds: u16) PunchResult {
        _ = timeout_seconds;

        // 构建传输信息
        const local_info = types.EndpointInfo{
            .local = self.local_addr orelse net.Address.initIp4(.{ 0, 0, 0, 0 }, 0),
            .local_ips = &.{},
            .machine_id = self.assigned_id,
            .machine_name = self.config.machine_name,
            .route_level = 8,
            .port_map_wan = self.config.port_map_wan,
            .port_map_lan = 0,
            .nat_type = self.local_nat_type,
        };

        // 解析对方地址 - 如果是同局域网，优先使用本地地址
        var remote_endpoints: [2]net.Address = undefined;
        var remote_count: usize = 0;

        if (begin.same_lan) {
            // 同局域网：优先使用本地地址
            if (begin.local_endpoint.len > 0) {
                if (parseEndpointString(begin.local_endpoint)) |addr| {
                    remote_endpoints[remote_count] = addr;
                    remote_count += 1;
                    log.debug("同局域网模式：使用本地地址 {s}", .{begin.local_endpoint});
                }
            }
            // 备选：公网地址
            if (begin.public_endpoint.len > 0) {
                if (parseEndpointString(begin.public_endpoint)) |addr| {
                    remote_endpoints[remote_count] = addr;
                    remote_count += 1;
                }
            }
        } else {
            // 跨网络：优先使用公网地址
            if (begin.public_endpoint.len > 0) {
                if (parseEndpointString(begin.public_endpoint)) |addr| {
                    remote_endpoints[remote_count] = addr;
                    remote_count += 1;
                }
            }
            if (begin.local_endpoint.len > 0) {
                if (parseEndpointString(begin.local_endpoint)) |addr| {
                    remote_endpoints[remote_count] = addr;
                    remote_count += 1;
                }
            }
        }

        if (remote_count == 0) {
            return PunchResult{
                .success = false,
                .error_message = "无法解析对方地址",
                .duration_ms = 0,
            };
        }

        const remote_info = types.EndpointInfo{
            .local = remote_endpoints[0],
            .local_ips = &.{},
            .machine_id = begin.source_machine_id,
            .machine_name = "",
            .route_level = 8,
            .port_map_wan = 0,
            .port_map_lan = 0,
            .nat_type = begin.source_nat_type,
        };

        const transport_info = types.TunnelTransportInfo{
            .transport_name = transport_type,
            .direction = begin.direction,
            .ssl = begin.ssl,
            .local = local_info,
            .remote = remote_info,
            .remote_endpoints = remote_endpoints[0..remote_count],
            .transaction_id = &begin.transaction_id,
            .flow_id = begin.flow_id,
        };

        log.debug("正在尝试 {s} 打洞，方向: {s}，目标地址: {d} 个", .{
            transport_type.description(),
            if (begin.direction == .forward) "正向" else "反向",
            remote_count,
        });

        // 调用传输管理器执行打洞
        const connection = self.transport_manager.connect(transport_type, &transport_info) catch |e| {
            const err_msg = switch (e) {
                error.Timeout, error.WouldBlock => "连接超时",
                error.ConnectionRefused => "连接被拒绝",
                else => "连接失败",
            };
            return PunchResult{
                .success = false,
                .error_message = err_msg,
                .duration_ms = 0,
            };
        };

        if (connection) |conn| {
            // 打洞连接建立成功，执行 Hello 握手验证
            var mutable_conn = conn;
            const is_initiator = (begin.direction == .forward);

            // 如果 Hello 握手已完成（对方已先完成打洞并发送了 Hello），直接返回成功
            if (mutable_conn.info.hello_completed) {
                log.info("Hello 握手已由对方完成，打洞连接已验证可用! ✓", .{});
                return PunchResult{
                    .success = true,
                    .connection = mutable_conn,
                    .error_message = "",
                    .duration_ms = 0,
                };
            }

            log.info("打洞连接已建立，正在执行 Hello 握手验证...", .{});

            const hello_success = mutable_conn.performHelloHandshake(is_initiator, 3000) catch |e| {
                log.err("Hello 握手异常: {any}", .{e});
                mutable_conn.close();
                return PunchResult{
                    .success = false,
                    .error_message = "Hello握手异常",
                    .duration_ms = 0,
                };
            };

            if (hello_success) {
                log.info("Hello 握手成功，打洞连接已验证可用! ✓", .{});
                return PunchResult{
                    .success = true,
                    .connection = mutable_conn,
                    .error_message = "",
                    .duration_ms = 0,
                };
            } else {
                log.warn("Hello 握手失败，连接不可用", .{});
                mutable_conn.close();
                return PunchResult{
                    .success = false,
                    .error_message = "Hello握手失败",
                    .duration_ms = 0,
                };
            }
        }

        return PunchResult{
            .success = false,
            .error_message = "打洞未成功",
            .duration_ms = 0,
        };
    }

    /// 打印打洞结果汇总
    fn printPunchResult(self: *const Self, result: *const AutoPunchResult, begin: *const protocol.PunchBegin) void {
        _ = self;
        log.info("", .{});
        log.info("╔══════════════════════════════════════════════════════════════╗", .{});
        if (result.success) {
            log.info("║           打洞完成 - 成功 ✓                                   ║", .{});
        } else {
            log.info("║           打洞完成 - 失败 ✗                                   ║", .{});
        }
        log.info("╠══════════════════════════════════════════════════════════════╣", .{});
        log.info("║ 目标节点:     {s}", .{begin.source_machine_id});
        log.info("║ 对方 NAT:     {s}", .{begin.source_nat_type.description()});
        log.info("║ 尝试方式数:   {d}", .{result.tried_methods});
        log.info("║ 总耗时:       {d} ms", .{result.total_duration_ms});
        if (result.successful_method) |method| {
            log.info("║ 成功方式:     {s}", .{method.description()});
        }
        log.info("╠══════════════════════════════════════════════════════════════╣", .{});
        log.info("║ 各方式尝试结果:", .{});

        var i: usize = 0;
        while (i < result.tried_methods and i < result.results.len) : (i += 1) {
            const r = result.results[i];
            const status = if (r.success) "✓" else "✗";
            if (r.error_message.len > 0) {
                log.info("║   {s} {s}: {d}ms - {s}", .{ status, r.transport_name, r.duration_ms, r.error_message });
            } else {
                log.info("║   {s} {s}: {d}ms", .{ status, r.transport_name, r.duration_ms });
            }
        }
        log.info("╚══════════════════════════════════════════════════════════════╝", .{});
    }

    /// 自动打洞 - 按配置文件中的优先级顺序尝试所有打洞方式
    pub fn autoPunch(self: *Self, target_id: []const u8, transports: []const config_mod.TransportConfig) !AutoPunchResult {
        var result = AutoPunchResult{
            .success = false,
            .tried_methods = 0,
            .successful_method = null,
            .connection = null,
            .total_duration_ms = 0,
            .results = undefined,
        };

        const start_time = std.time.milliTimestamp();

        log.info("", .{});
        log.info("╔══════════════════════════════════════════════════════════════╗", .{});
        log.info("║              开始自动打洞                                    ║", .{});
        log.info("╠══════════════════════════════════════════════════════════════╣", .{});
        log.info("║ 目标节点: {s}", .{target_id});
        log.info("║ 待尝试方式数: {d}", .{transports.len});
        log.info("╚══════════════════════════════════════════════════════════════╝", .{});
        log.info("", .{});

        var method_idx: usize = 0;
        for (transports) |transport_config| {
            if (!transport_config.enabled) {
                log.debug("跳过已禁用的打洞方式: {s}", .{transport_config.name});
                continue;
            }

            const transport_type = config_mod.ClientConfiguration.getTransportType(transport_config.name) orelse {
                log.warn("未知的打洞方式: {s}", .{transport_config.name});
                continue;
            };

            if (method_idx >= result.results.len) break;

            result.tried_methods += 1;
            const method_start = std.time.milliTimestamp();

            log.info("", .{});
            log.info("┌──────────────────────────────────────────────────────────────┐", .{});
            log.info("│ [{d}/{d}] 尝试打洞方式: {s}", .{ result.tried_methods, transports.len, transport_config.name });
            log.info("│ 优先级: {d}, 超时: {d}s, 重试: {d}次", .{
                transport_config.priority,
                transport_config.timeout_seconds,
                transport_config.retry_count,
            });
            log.info("└──────────────────────────────────────────────────────────────┘", .{});

            // 尝试打洞（带重试）
            var retry: u8 = 0;
            var punch_result: PunchResult = undefined;
            while (retry <= transport_config.retry_count) : (retry += 1) {
                if (retry > 0) {
                    log.info("  重试第 {d}/{d} 次...", .{ retry, transport_config.retry_count });
                }

                punch_result = self.requestPunch(target_id, transport_type) catch |e| {
                    log.err("  打洞请求异常: {any}", .{e});
                    punch_result = PunchResult{
                        .success = false,
                        .error_message = "请求异常",
                        .duration_ms = 0,
                    };
                    continue;
                };

                if (punch_result.success) {
                    break;
                }

                // 短暂等待后重试
                if (retry < transport_config.retry_count) {
                    std.Thread.sleep(500 * std.time.ns_per_ms);
                }
            }

            const method_duration = @as(u64, @intCast(std.time.milliTimestamp() - method_start));

            // 记录结果
            result.results[method_idx] = .{
                .transport_name = transport_config.name,
                .success = punch_result.success,
                .duration_ms = method_duration,
                .error_message = punch_result.error_message,
            };
            method_idx += 1;

            if (punch_result.success) {
                log.info("", .{});
                log.info("╔══════════════════════════════════════════════════════════════╗", .{});
                log.info("║  ✓ 打洞成功!                                                 ║", .{});
                log.info("╠══════════════════════════════════════════════════════════════╣", .{});
                log.info("║ 使用方式: {s}", .{transport_config.name});
                log.info("║ 耗时: {d} ms", .{method_duration});
                log.info("╚══════════════════════════════════════════════════════════════╝", .{});

                result.success = true;
                result.successful_method = transport_type;
                result.connection = punch_result.connection;
                break;
            } else {
                log.warn("  ✗ 打洞失败: {s} (耗时: {d}ms)", .{ punch_result.error_message, method_duration });
            }
        }

        result.total_duration_ms = @intCast(std.time.milliTimestamp() - start_time);

        // 打印最终结果摘要
        log.info("", .{});
        log.info("╔══════════════════════════════════════════════════════════════╗", .{});
        if (result.success) {
            log.info("║              自动打洞完成 - 成功                              ║", .{});
        } else {
            log.info("║              自动打洞完成 - 失败                              ║", .{});
        }
        log.info("╠══════════════════════════════════════════════════════════════╣", .{});
        log.info("║ 尝试方式数: {d}", .{result.tried_methods});
        log.info("║ 总耗时: {d} ms", .{result.total_duration_ms});
        if (result.successful_method) |method| {
            log.info("║ 成功方式: {s}", .{method.name()});
        }
        log.info("╠══════════════════════════════════════════════════════════════╣", .{});
        log.info("║ 详细结果:", .{});
        for (result.results[0..method_idx]) |r| {
            const status = if (r.success) "✓" else "✗";
            log.info("║   {s} {s}: {d}ms {s}", .{ status, r.transport_name, r.duration_ms, r.error_message });
        }
        log.info("╚══════════════════════════════════════════════════════════════╝", .{});

        return result;
    }
};

/// 自动打洞结果
pub const AutoPunchResult = struct {
    /// 是否成功
    success: bool,
    /// 尝试的方式数量
    tried_methods: u32,
    /// 成功的方式
    successful_method: ?types.TransportType,
    /// 连接
    connection: ?transport_mod.ITunnelConnection,
    /// 总耗时
    total_duration_ms: u64,
    /// 每种方式的结果
    results: [8]MethodResult = undefined,

    pub const MethodResult = struct {
        transport_name: []const u8 = "",
        success: bool = false,
        duration_ms: u64 = 0,
        error_message: []const u8 = "",
    };
};

/// 客户端入口函数
pub fn main() !void {
    // 初始化控制台，支持 UTF-8 中文显示
    zzig.Console.setup();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 解析命令行参数
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var config_path: []const u8 = "punch_client.json";
    var target_id: ?[]const u8 = null;
    var transport_str: ?[]const u8 = null;
    var list_only = false;
    var auto_mode = false;
    var cmd_server_addr: ?[]const u8 = null;
    var cmd_server_port: ?u16 = null;
    var cmd_machine_name: ?[]const u8 = null;
    // TLS 相关命令行参数
    var cmd_tls_enabled: ?bool = null;
    var cmd_tls_skip_verify: ?bool = null;

    // 简单参数解析
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            if (i + 1 < args.len) {
                config_path = args[i + 1];
                i += 1;
            }
        } else if (std.mem.eql(u8, arg, "-s") or std.mem.eql(u8, arg, "--server")) {
            if (i + 1 < args.len) {
                const addr_arg = args[i + 1];
                // 支持 host:port 格式
                if (std.mem.lastIndexOfScalar(u8, addr_arg, ':')) |colon_idx| {
                    cmd_server_addr = addr_arg[0..colon_idx];
                    cmd_server_port = std.fmt.parseInt(u16, addr_arg[colon_idx + 1 ..], 10) catch null;
                } else {
                    cmd_server_addr = addr_arg;
                }
                i += 1;
            }
        } else if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--port")) {
            if (i + 1 < args.len) {
                cmd_server_port = std.fmt.parseInt(u16, args[i + 1], 10) catch 7891;
                i += 1;
            }
        } else if (std.mem.eql(u8, arg, "-n") or std.mem.eql(u8, arg, "--name")) {
            if (i + 1 < args.len) {
                cmd_machine_name = args[i + 1];
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
        } else if (std.mem.eql(u8, arg, "-a") or std.mem.eql(u8, arg, "--auto")) {
            auto_mode = true;
        } else if (std.mem.eql(u8, arg, "--auto-punch")) {
            // 自动与新上线节点打洞
            auto_mode = true;
        } else if (std.mem.eql(u8, arg, "-l") or std.mem.eql(u8, arg, "--list")) {
            list_only = true;
        } else if (std.mem.eql(u8, arg, "--tls")) {
            // 启用 TLS
            cmd_tls_enabled = true;
        } else if (std.mem.eql(u8, arg, "--no-tls")) {
            // 禁用 TLS
            cmd_tls_enabled = false;
        } else if (std.mem.eql(u8, arg, "--skip-verify") or std.mem.eql(u8, arg, "-k")) {
            // 跳过证书验证 (类似 curl -k)
            cmd_tls_skip_verify = true;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printUsage();
            return;
        }
    }

    // 加载配置文件
    var config_manager = config_mod.ConfigManager.init(allocator, config_path);
    defer config_manager.deinit();

    config_manager.load() catch |e| {
        log.err("加载配置文件失败: {any}", .{e});
        log.info("将使用默认配置", .{});
    };

    // 应用日志配置
    config_manager.applyLogConfig();

    // 命令行参数覆盖配置文件
    const client_config = ClientConfig{
        .server_addr = cmd_server_addr orelse config_manager.config.server_addr,
        .server_port = cmd_server_port orelse config_manager.config.server_port,
        .machine_name = cmd_machine_name orelse config_manager.config.machine_name,
        .machine_id = config_manager.config.machine_id,
        .heartbeat_interval = config_manager.config.heartbeat_interval,
        .port_map_wan = config_manager.config.port_map_wan,
        .stun_server = config_manager.config.stun_server,
        .stun_port = config_manager.config.stun_port,
        .auto_detect_nat = config_manager.config.auto_detect_nat,
        // TLS 配置：命令行参数优先于配置文件
        // skip_verify 是 verify_server 的反向逻辑
        .tls_enabled = cmd_tls_enabled orelse config_manager.config.tls.enabled,
        .tls_skip_verify = cmd_tls_skip_verify orelse !config_manager.config.tls.verify_server,
        // 自动打洞：命令行 --auto-punch 或配置文件中启用
        .auto_punch_on_peer_online = auto_mode or config_manager.config.auto_punch_on_peer_online,
        // 传输方式配置
        .transports = config_manager.config.transports,
    };

    log.info("", .{});
    log.info("╔══════════════════════════════════════════════════════════════╗", .{});
    log.info("║              打洞客户端启动                                  ║", .{});
    log.info("╚══════════════════════════════════════════════════════════════╝", .{});
    log.info("", .{});

    var client = PunchClient.init(allocator, client_config);
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

        log.info("", .{});
        log.info("┌────────────────────────────────────────────────────────────────┐", .{});
        log.info("│                    在线节点列表                                │", .{});
        log.info("├────┬──────────────────┬──────────────────┬─────────────────────┤", .{});
        log.info("│ #  │ ID               │ 名称             │ NAT类型             │", .{});
        log.info("├────┼──────────────────┼──────────────────┼─────────────────────┤", .{});

        if (peers.items.len == 0) {
            log.info("│                    (无其他在线节点)                           │", .{});
        } else {
            for (peers.items, 0..) |peer, idx| {
                // 格式化 ID
                var id_buf: [16]u8 = undefined;
                @memset(&id_buf, ' ');
                const id_len = @min(peer.machine_id.len, 16);
                @memcpy(id_buf[0..id_len], peer.machine_id[0..id_len]);

                // 格式化名称
                var name_buf: [16]u8 = undefined;
                @memset(&name_buf, ' ');
                const name_len = @min(peer.machine_name.len, 16);
                @memcpy(name_buf[0..name_len], peer.machine_name[0..name_len]);

                log.info("│ {d: >2} │ {s} │ {s} │ {s: <19} │", .{
                    idx + 1,
                    id_buf,
                    name_buf,
                    peer.nat_type.description(),
                });
            }
        }
        log.info("└────┴──────────────────┴──────────────────┴─────────────────────┘", .{});
        log.info("", .{});
    } else if (target_id) |tid| {
        if (auto_mode or transport_str == null) {
            // 自动模式：按配置顺序尝试所有打洞方式
            log.info("使用自动模式，将按配置顺序尝试所有打洞方式", .{});

            const result = try client.autoPunch(tid, config_manager.config.transports);

            if (result.success) {
                log.info("自动打洞成功! 可以开始通信", .{});

                if (result.connection) |*conn| {
                    var connection = conn.*;
                    _ = connection.send("Hello from Zig Auto Punch!") catch {};
                    connection.close();
                }
            } else {
                log.err("自动打洞失败，所有方式均未成功", .{});
            }
        } else {
            // 指定方式打洞
            const transport_type = parseTransportType(transport_str.?);
            log.info("使用指定方式打洞: {s}", .{transport_type.name()});

            const result = try client.requestPunch(tid, transport_type);

            if (result.success) {
                log.info("打洞成功! 可以开始通信", .{});

                if (result.connection) |*conn| {
                    var connection = conn.*;
                    _ = connection.send("Hello from Zig!") catch {};
                    connection.close();
                }
            } else {
                log.err("打洞失败: {s}", .{result.error_message});
            }
        }
    } else {
        // 等待其他节点连接
        log.info("等待打洞请求...", .{});
        log.info("提示: 使用 -t <目标ID> 来发起打洞", .{});
        try client.runLoop();
    }
}

fn parseTransportType(str: []const u8) types.TransportType {
    if (std.mem.eql(u8, str, "udp")) return .udp;
    if (std.mem.eql(u8, str, "udp_p2p_nat") or std.mem.eql(u8, str, "udp-p2p")) return .udp_p2p_nat;
    if (std.mem.eql(u8, str, "tcp_p2p_nat") or std.mem.eql(u8, str, "tcp-p2p")) return .tcp_p2p_nat;
    if (std.mem.eql(u8, str, "tcp_nutssb") or std.mem.eql(u8, str, "tcp-ttl")) return .tcp_nutssb;
    if (std.mem.eql(u8, str, "udp_port_map") or std.mem.eql(u8, str, "udp-map")) return .udp_port_map;
    if (std.mem.eql(u8, str, "tcp_port_map") or std.mem.eql(u8, str, "tcp-map")) return .tcp_port_map;
    if (std.mem.eql(u8, str, "msquic") or std.mem.eql(u8, str, "quic")) return .msquic;
    return .udp;
}

fn printUsage() void {
    const usage =
        \\打洞客户端 (支持配置文件和自动打洞)
        \\
        \\用法: client [选项]
        \\
        \\选项:
        \\  -c, --config <路径>   配置文件路径 (默认: punch_client.json)
        \\  -s, --server <地址>   服务器地址 (覆盖配置文件)
        \\  -p, --port <端口>     服务器端口 (覆盖配置文件)
        \\  -n, --name <名称>     本机名称 (覆盖配置文件)
        \\  -t, --target <ID>     目标节点 ID (发起打洞)
        \\  -m, --method <方式>   传输方式 (指定单一方式):
        \\                          udp       - UDP 打洞
        \\                          udp-p2p   - UDP 同时打开
        \\                          tcp-p2p   - TCP 同时打开
        \\                          tcp-ttl   - TCP 低 TTL
        \\                          udp-map   - UDP 端口映射
        \\                          tcp-map   - TCP 端口映射
        \\                          quic      - MsQuic
        \\  -a, --auto            自动模式 (按配置顺序尝试所有打洞方式)
        \\  --auto-punch          监听新节点上线并自动打洞
        \\  -l, --list            列出在线节点
        \\
        \\TLS 选项:
        \\  --tls                 强制启用 TLS 加密 (默认已启用)
        \\  --no-tls              禁用 TLS 加密 (仅用于本地调试)
        \\  -k, --skip-verify     跳过服务器证书验证 (用于自签名证书)
        \\
        \\  -h, --help            显示帮助信息
        \\
        \\配置文件说明:
        \\  首次运行时会自动生成默认配置文件 punch_client.json
        \\  配置文件包含服务器设置、NAT 设置、TLS 设置和打洞方式优先级
        \\  可编辑配置文件调整打洞方式的启用状态和优先级
        \\
        \\示例:
        \\  # 使用默认配置连接服务器并等待连接
        \\  client
        \\
        \\  # 使用指定配置文件
        \\  client -c /path/to/config.json
        \\
        \\  # 列出在线节点
        \\  client -l
        \\
        \\  # 自动模式向指定节点打洞 (按配置优先级尝试)
        \\  client -t node123 -a
        \\
        \\  # 监听新节点上线并自动打洞
        \\  client --auto-punch
        \\
        \\  # 向指定节点发起指定方式打洞
        \\  client -t node123 -m udp
        \\
        \\  # 命令行参数覆盖配置文件
        \\  client -s 192.168.1.100 -p 7891 -n "我的电脑"
        \\
        \\  # 使用自签名证书连接 (跳过验证)
        \\  client -s example.com -k
        \\
        \\  # 本地调试禁用 TLS
        \\  client -s 127.0.0.1 --no-tls
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
    try std.testing.expectEqual(types.TransportType.udp_p2p_nat, parseTransportType("udp-p2p"));
    try std.testing.expectEqual(types.TransportType.tcp_p2p_nat, parseTransportType("tcp-p2p"));
    try std.testing.expectEqual(types.TransportType.tcp_nutssb, parseTransportType("tcp-ttl"));
    try std.testing.expectEqual(types.TransportType.udp, parseTransportType("unknown"));
}
