//! 信令协议模块
//! 定义服务端和客户端之间的通信协议
//! 用于协调打洞过程

const std = @import("std");
const net = std.net;
const types = @import("types.zig");

/// 协议版本
pub const PROTOCOL_VERSION: u8 = 1;

/// 协议魔数
pub const PROTOCOL_MAGIC: u32 = 0x5A4C4E4B; // "ZLNK"

/// 消息类型
pub const MessageType = enum(u8) {
    /// 注册请求
    register = 0x01,
    /// 注册响应
    register_response = 0x02,
    /// 心跳
    heartbeat = 0x03,
    /// 心跳响应
    heartbeat_response = 0x04,
    /// 打洞请求
    punch_request = 0x10,
    /// 打洞开始通知
    punch_begin = 0x11,
    /// 打洞成功通知
    punch_success = 0x12,
    /// 打洞失败通知
    punch_fail = 0x13,
    /// 打洞响应
    punch_response = 0x14,
    /// 查询节点
    query_peer = 0x20,
    /// 查询响应
    query_response = 0x21,
    /// 列出在线客户端
    list_peers = 0x22,
    /// 列出在线客户端响应
    list_peers_response = 0x23,
    /// NAT 信息
    nat_info = 0x30,
    /// 错误响应
    error_response = 0xFF,
    _,

    pub fn toString(self: MessageType) []const u8 {
        return switch (self) {
            .register => "注册请求",
            .register_response => "注册响应",
            .heartbeat => "心跳",
            .heartbeat_response => "心跳响应",
            .punch_request => "打洞请求",
            .punch_begin => "打洞开始",
            .punch_success => "打洞成功",
            .punch_fail => "打洞失败",
            .query_peer => "查询节点",
            .query_response => "查询响应",
            .nat_info => "NAT信息",
            .error_response => "错误响应",
            _ => "未知消息",
        };
    }
};

/// 错误码
pub const ErrorCode = enum(u16) {
    /// 成功
    success = 0,
    /// 未知错误
    unknown = 1,
    /// 节点不存在
    peer_not_found = 100,
    /// 节点离线
    peer_offline = 101,
    /// 打洞超时
    punch_timeout = 200,
    /// 打洞被拒绝
    punch_rejected = 201,
    /// 协议错误
    protocol_error = 300,
    /// 版本不匹配
    version_mismatch = 301,
    /// 认证失败
    auth_failed = 400,
    _,

    pub fn message(self: ErrorCode) []const u8 {
        return switch (self) {
            .success => "成功",
            .unknown => "未知错误",
            .peer_not_found => "节点不存在",
            .peer_offline => "节点离线",
            .punch_timeout => "打洞超时",
            .punch_rejected => "打洞被拒绝",
            .protocol_error => "协议错误",
            .version_mismatch => "版本不匹配",
            .auth_failed => "认证失败",
            _ => "未知错误",
        };
    }
};

/// 协议消息头部 (16 字节)
pub const MessageHeader = extern struct {
    /// 魔数
    magic: u32 align(1) = PROTOCOL_MAGIC,
    /// 版本
    version: u8 align(1) = PROTOCOL_VERSION,
    /// 消息类型
    msg_type: MessageType align(1) = .heartbeat,
    /// 保留字段
    reserved: u16 align(1) = 0,
    /// 序列号
    sequence: u32 align(1) = 0,
    /// 数据长度
    data_length: u32 align(1) = 0,

    pub const SIZE: usize = 16;

    /// 序列化到缓冲区
    pub fn serialize(self: *const MessageHeader, buf: []u8) !void {
        if (buf.len < SIZE) return error.BufferTooSmall;

        std.mem.writeInt(u32, buf[0..4], self.magic, .big);
        buf[4] = self.version;
        buf[5] = @intFromEnum(self.msg_type);
        std.mem.writeInt(u16, buf[6..8], self.reserved, .big);
        std.mem.writeInt(u32, buf[8..12], self.sequence, .big);
        std.mem.writeInt(u32, buf[12..16], self.data_length, .big);
    }

    /// 从缓冲区解析
    pub fn parse(buf: []const u8) !MessageHeader {
        if (buf.len < SIZE) return error.BufferTooSmall;

        const magic = std.mem.readInt(u32, buf[0..4], .big);
        if (magic != PROTOCOL_MAGIC) return error.InvalidMagic;

        return MessageHeader{
            .magic = magic,
            .version = buf[4],
            .msg_type = @enumFromInt(buf[5]),
            .reserved = std.mem.readInt(u16, buf[6..8], .big),
            .sequence = std.mem.readInt(u32, buf[8..12], .big),
            .data_length = std.mem.readInt(u32, buf[12..16], .big),
        };
    }
};

/// 节点信息 (用于注册和查询)
pub const PeerInfo = struct {
    /// 机器 ID
    machine_id: []const u8,
    /// 机器名称
    machine_name: []const u8,
    /// 本地端点
    local_endpoint: net.Address,
    /// 公网端点
    public_endpoint: ?net.Address,
    /// NAT 类型
    nat_type: types.NatType,
    /// 支持的传输方式
    supported_transports: []const types.TransportType,
    /// 路由层级
    route_level: u8,
    /// 端口映射 (外网)
    port_map_wan: u16,
    /// 端口映射 (内网)
    port_map_lan: u16,

    /// 序列化
    pub fn serialize(self: *const PeerInfo, allocator: std.mem.Allocator) ![]u8 {
        var list: std.ArrayList(u8) = .{};
        errdefer list.deinit(allocator);

        const writer = list.writer(allocator);

        // 机器 ID (长度前缀)
        try writer.writeInt(u16, @intCast(self.machine_id.len), .big);
        try writer.writeAll(self.machine_id);

        // 机器名称 (长度前缀)
        try writer.writeInt(u16, @intCast(self.machine_name.len), .big);
        try writer.writeAll(self.machine_name);

        // NAT 类型
        try writer.writeByte(@intFromEnum(self.nat_type));

        // 路由层级
        try writer.writeByte(self.route_level);

        // 端口映射
        try writer.writeInt(u16, self.port_map_wan, .big);
        try writer.writeInt(u16, self.port_map_lan, .big);

        // 本地端点
        try serializeAddress(&self.local_endpoint, writer);

        // 公网端点
        if (self.public_endpoint) |pub_ep| {
            try writer.writeByte(1);
            try serializeAddress(&pub_ep, writer);
        } else {
            try writer.writeByte(0);
        }

        // 支持的传输方式
        try writer.writeByte(@intCast(self.supported_transports.len));
        for (self.supported_transports) |t| {
            try writer.writeByte(@intFromEnum(t));
        }

        return try list.toOwnedSlice(allocator);
    }

    /// 反序列化
    pub fn parse(data: []const u8, allocator: std.mem.Allocator) !PeerInfo {
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        // 机器 ID
        const id_len = try reader.readInt(u16, .big);
        const machine_id = try allocator.alloc(u8, id_len);
        _ = try reader.readAll(machine_id);

        // 机器名称
        const name_len = try reader.readInt(u16, .big);
        const machine_name = try allocator.alloc(u8, name_len);
        _ = try reader.readAll(machine_name);

        // NAT 类型
        const nat_type: types.NatType = @enumFromInt(try reader.readByte());

        // 路由层级
        const route_level = try reader.readByte();

        // 端口映射
        const port_map_wan = try reader.readInt(u16, .big);
        const port_map_lan = try reader.readInt(u16, .big);

        // 本地端点
        const local_endpoint = try parseAddress(reader);

        // 公网端点
        const has_public = try reader.readByte() != 0;
        const public_endpoint = if (has_public) try parseAddress(reader) else null;

        // 支持的传输方式
        const transport_count = try reader.readByte();
        const transports = try allocator.alloc(types.TransportType, transport_count);
        for (transports) |*t| {
            t.* = @enumFromInt(try reader.readByte());
        }

        return PeerInfo{
            .machine_id = machine_id,
            .machine_name = machine_name,
            .local_endpoint = local_endpoint,
            .public_endpoint = public_endpoint,
            .nat_type = nat_type,
            .supported_transports = transports,
            .route_level = route_level,
            .port_map_wan = port_map_wan,
            .port_map_lan = port_map_lan,
        };
    }
};

/// 打洞请求数据
pub const PunchRequest = struct {
    /// 目标机器 ID
    target_machine_id: []const u8,
    /// 传输方式
    transport: types.TransportType,
    /// 方向
    direction: types.TunnelDirection,
    /// 事务 ID
    transaction_id: [16]u8,
    /// 流 ID
    flow_id: u32,
    /// 是否需要 SSL
    ssl: bool,

    pub fn serialize(self: *const PunchRequest, allocator: std.mem.Allocator) ![]u8 {
        var list: std.ArrayList(u8) = .{};
        errdefer list.deinit(allocator);

        const writer = list.writer(allocator);

        // 目标机器 ID
        try writer.writeInt(u16, @intCast(self.target_machine_id.len), .big);
        try writer.writeAll(self.target_machine_id);

        // 传输方式
        try writer.writeByte(@intFromEnum(self.transport));

        // 方向
        try writer.writeByte(@intFromEnum(self.direction));

        // 事务 ID
        try writer.writeAll(&self.transaction_id);

        // 流 ID
        try writer.writeInt(u32, self.flow_id, .big);

        // SSL
        try writer.writeByte(if (self.ssl) 1 else 0);

        return try list.toOwnedSlice(allocator);
    }

    /// 从缓冲区解析
    pub fn parse(data: []const u8) ?PunchRequest {
        if (data.len < 26) return null; // 最小长度

        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        // 目标机器 ID
        const id_len = reader.readInt(u16, .big) catch return null;
        if (data.len < 2 + id_len + 24) return null;
        const target_id_end = 2 + id_len;
        const target_machine_id = data[2..target_id_end];

        // 跳过已读取的 ID
        reader.skipBytes(id_len, .{}) catch return null;

        // 传输方式
        const transport: types.TransportType = @enumFromInt(reader.readByte() catch return null);

        // 方向
        const direction: types.TunnelDirection = @enumFromInt(reader.readByte() catch return null);

        // 事务 ID
        var transaction_id: [16]u8 = undefined;
        _ = reader.readAll(&transaction_id) catch return null;

        // 流 ID
        const flow_id = reader.readInt(u32, .big) catch return null;

        // SSL
        const ssl = (reader.readByte() catch return null) == 1;

        return PunchRequest{
            .target_machine_id = target_machine_id,
            .transport = transport,
            .direction = direction,
            .transaction_id = transaction_id,
            .flow_id = flow_id,
            .ssl = ssl,
        };
    }
};

/// 打洞开始通知（简化版本，用于 client 解析）
pub const PunchBegin = struct {
    /// 源机器 ID
    source_machine_id: []const u8,
    /// 源 NAT 类型
    source_nat_type: types.NatType,
    /// 传输方式
    transport: types.TransportType,
    /// 方向
    direction: types.TunnelDirection,
    /// 事务 ID
    transaction_id: [16]u8,
    /// 流 ID
    flow_id: u32,
    /// 是否需要 SSL
    ssl: bool,
    /// 原始数据引用
    _raw_data: []const u8,

    /// 简化的解析方法
    pub fn parse(data: []const u8) ?PunchBegin {
        if (data.len < 24) return null;

        // 解析源机器 ID 长度
        const id_len = std.mem.readInt(u16, data[0..2], .big);
        if (data.len < 2 + id_len + 22) return null;

        const source_id = data[2 .. 2 + id_len];
        var offset: usize = 2 + id_len;

        // 源 NAT 类型
        const nat_byte = data[offset];
        offset += 1;
        const source_nat = @as(types.NatType, @enumFromInt(nat_byte));

        // 传输方式
        const transport_byte = data[offset];
        offset += 1;
        const transport = @as(types.TransportType, @enumFromInt(transport_byte));

        // 方向
        const direction_byte = data[offset];
        offset += 1;
        const direction = @as(types.TunnelDirection, @enumFromInt(direction_byte));

        // 事务 ID
        if (offset + 16 > data.len) return null;
        var transaction_id: [16]u8 = undefined;
        @memcpy(&transaction_id, data[offset .. offset + 16]);
        offset += 16;

        // 流 ID
        if (offset + 4 > data.len) return null;
        const flow_id = std.mem.readInt(u32, data[offset .. offset + 4][0..4], .big);
        offset += 4;

        // SSL
        const ssl = if (offset < data.len) data[offset] != 0 else false;

        return PunchBegin{
            .source_machine_id = source_id,
            .source_nat_type = source_nat,
            .transport = transport,
            .direction = direction,
            .transaction_id = transaction_id,
            .flow_id = flow_id,
            .ssl = ssl,
            ._raw_data = data,
        };
    }

    /// 获取解析后的数据大小
    pub fn getSize(self: *const PunchBegin) usize {
        // 2 (id_len) + id + 1 (nat) + 1 (transport) + 1 (direction) + 16 (txn_id) + 4 (flow_id) + 1 (ssl)
        return 2 + self.source_machine_id.len + 24;
    }
};

/// 序列化地址
fn serializeAddress(addr: *const net.Address, writer: anytype) !void {
    // Windows 上 AF 是 struct 常量，使用数值比较
    if (addr.any.family == 2) { // AF_INET
        try writer.writeByte(4); // IPv4
        const addr_in = @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&addr.any)));
        try writer.writeAll(@as(*const [4]u8, @ptrCast(&addr_in.addr)));
        try writer.writeInt(u16, std.mem.bigToNative(u16, addr_in.port), .big);
    } else if (addr.any.family == 10 or addr.any.family == 23) { // AF_INET6 Linux=10, Windows=23
        try writer.writeByte(6); // IPv6
        const addr_in6 = @as(*const std.posix.sockaddr.in6, @ptrCast(@alignCast(&addr.any)));
        try writer.writeAll(@as(*const [16]u8, @ptrCast(&addr_in6.addr)));
        try writer.writeInt(u16, std.mem.bigToNative(u16, addr_in6.port), .big);
    } else {
        try writer.writeByte(0);
    }
}

/// 解析地址
fn parseAddress(reader: anytype) !net.Address {
    const addr_type = try reader.readByte();

    if (addr_type == 4) {
        // IPv4
        var ip_bytes: [4]u8 = undefined;
        _ = try reader.readAll(&ip_bytes);
        const port = try reader.readInt(u16, .big);
        return net.Address.initIp4(ip_bytes, port);
    } else if (addr_type == 6) {
        // IPv6
        var ip_bytes: [16]u8 = undefined;
        _ = try reader.readAll(&ip_bytes);
        const port = try reader.readInt(u16, .big);
        return net.Address.initIp6(ip_bytes, port, 0, 0);
    }

    return error.InvalidAddress;
}

/// 生成随机事务 ID
pub fn generateTransactionId() [16]u8 {
    var id: [16]u8 = undefined;
    std.posix.getrandom(&id) catch {
        // 备用：使用时间戳填充
        const ts: u64 = @intCast(std.time.milliTimestamp());
        std.mem.writeInt(u64, id[0..8], ts, .little);
        std.mem.writeInt(u64, id[8..16], ts ^ 0xDEADBEEF, .little);
    };
    return id;
}

/// 全局序列号计数器
var global_sequence: u32 = 0;

/// 获取下一个序列号
pub fn nextSequence() u32 {
    return @atomicRmw(u32, &global_sequence, .Add, 1, .seq_cst);
}

test "MessageHeader serialize and parse" {
    const header = MessageHeader{
        .msg_type = .punch_request,
        .sequence = 12345,
        .data_length = 100,
    };

    var buf: [16]u8 = undefined;
    try header.serialize(&buf);

    const parsed = try MessageHeader.parse(&buf);
    try std.testing.expect(parsed.msg_type == .punch_request);
    try std.testing.expect(parsed.sequence == 12345);
    try std.testing.expect(parsed.data_length == 100);
}

test "generateTransactionId" {
    const id1 = generateTransactionId();
    const id2 = generateTransactionId();

    // 两次生成的 ID 应该不同
    try std.testing.expect(!std.mem.eql(u8, &id1, &id2));
}
