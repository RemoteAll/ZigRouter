//! QUIC 模块
//!
//! 纯 Zig 实现的 QUIC 协议栈
//!
//! ## 功能
//! - QUIC v1 (RFC 9000) 和 v2 (RFC 9369) 支持
//! - TLS 1.3 集成 (RFC 9001)
//! - 丢包检测与拥塞控制 (RFC 9002)
//! - 0-RTT 连接恢复
//! - 连接迁移
//!
//! ## 使用示例
//!
//! ### 客户端
//! ```zig
//! const quic = @import("quic");
//!
//! // 创建连接
//! var conn = try quic.Connection.initClient(
//!     allocator,
//!     quic.TransportParameters.defaultClient(),
//! );
//! defer conn.deinit();
//!
//! // 发起连接
//! var initial_packet: [1350]u8 = undefined;
//! const len = try conn.generateInitialPacket(&initial_packet);
//! try socket.send(initial_packet[0..len]);
//!
//! // 处理响应
//! var buf: [65535]u8 = undefined;
//! const recv_len = try socket.recv(&buf);
//! try conn.receive(buf[0..recv_len]);
//!
//! // 发送数据
//! const stream_id = try conn.openBidiStream();
//! try conn.sendStreamData(stream_id, "Hello, QUIC!", false);
//! ```
//!
//! ### 服务端
//! ```zig
//! const quic = @import("quic");
//!
//! // 接收初始包
//! var buf: [65535]u8 = undefined;
//! const recv_len = try socket.recv(&buf);
//!
//! // 解析包头获取连接 ID
//! const header = try quic.LongHeader.decode(buf[0..recv_len]);
//!
//! // 创建连接
//! var conn = try quic.Connection.initServer(
//!     allocator,
//!     quic.TransportParameters.defaultServer(),
//!     header.dest_cid,
//!     header.src_cid,
//! );
//! defer conn.deinit();
//!
//! // 处理包
//! try conn.receive(buf[0..recv_len]);
//! ```

const std = @import("std");

// 导出子模块
pub const types = @import("types.zig");
pub const packet = @import("packet.zig");
pub const frame = @import("frame.zig");
pub const tls = @import("tls.zig");
pub const crypto = @import("crypto.zig");
pub const connection = @import("connection.zig");
pub const recovery = @import("recovery.zig");
pub const client = @import("client.zig");
pub const server = @import("server.zig");

// 常用类型导出
pub const Version = types.Version;
pub const PacketType = types.PacketType;
pub const ConnectionId = types.ConnectionId;
pub const StreamId = types.StreamId;
pub const TransportParameters = types.TransportParameters;
pub const TransportError = types.TransportError;
pub const PacketNumberSpace = types.PacketNumberSpace;

pub const LongHeader = packet.LongHeader;
pub const ShortHeader = packet.ShortHeader;
pub const Packet = packet.Packet;

pub const Frame = frame.Frame;
pub const FrameDecoder = frame.FrameDecoder;
pub const FrameEncoder = frame.FrameEncoder;

pub const Keys = tls.Keys;
pub const PacketProtector = tls.PacketProtector;
pub const CipherSuite = tls.CipherSuite;

pub const CryptoContext = crypto.CryptoContext;
pub const HandshakeState = crypto.HandshakeState;

pub const Connection = connection.Connection;
pub const ConnectionState = connection.ConnectionState;
pub const Role = connection.Role;
pub const Stream = connection.Stream;
pub const StreamState = connection.StreamState;

pub const LossDetector = recovery.LossDetector;
pub const CongestionController = recovery.CongestionController;
pub const RttEstimator = recovery.RttEstimator;
pub const SentPacket = recovery.SentPacket;

// Client/Server API
pub const QuicClient = client.QuicClient;
pub const ClientConfig = client.ClientConfig;
pub const ClientEvent = client.ClientEvent;

pub const QuicServer = server.QuicServer;
pub const ServerConfig = server.ServerConfig;
pub const ServerEvent = server.ServerEvent;
pub const ServerConnection = server.ServerConnection;

// VarInt 编解码
pub const decodeVarInt = types.decodeVarInt;
pub const encodeVarInt = types.encodeVarInt;
pub const varIntLen = types.varIntLen;

/// QUIC 事件
pub const Event = union(enum) {
    /// 连接已建立
    connected: void,
    /// 收到数据
    stream_data: struct {
        stream_id: StreamId,
        data: []const u8,
        fin: bool,
    },
    /// 流已打开
    stream_opened: StreamId,
    /// 流已关闭
    stream_closed: StreamId,
    /// 连接关闭
    connection_closed: struct {
        error_code: u64,
        reason: []const u8,
        is_application: bool,
    },
    /// 需要发送数据
    datagrams_to_send: void,
    /// 需要等待超时
    timeout: u64, // 纳秒
};

/// 检查版本是否支持
pub fn isVersionSupported(version: u32) bool {
    return switch (version) {
        @intFromEnum(Version.v1) => true,
        @intFromEnum(Version.v2) => true,
        else => false,
    };
}

/// 生成版本协商包
pub fn generateVersionNegotiation(
    allocator: std.mem.Allocator,
    dcid: *const ConnectionId,
    scid: *const ConnectionId,
) ![]u8 {
    const len = 1 + 4 + 1 + dcid.len + 1 + scid.len + 4 + 4;
    const buf = try allocator.alloc(u8, len);

    var offset: usize = 0;

    // 固定位（长包头，随机类型）
    var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
    buf[offset] = 0x80 | (prng.random().int(u8) & 0x7F);
    offset += 1;

    // 版本 = 0（版本协商）
    @memset(buf[offset .. offset + 4], 0);
    offset += 4;

    // DCID
    buf[offset] = dcid.len;
    offset += 1;
    @memcpy(buf[offset .. offset + dcid.len], dcid.id[0..dcid.len]);
    offset += dcid.len;

    // SCID
    buf[offset] = scid.len;
    offset += 1;
    @memcpy(buf[offset .. offset + scid.len], scid.id[0..scid.len]);
    offset += scid.len;

    // 支持的版本
    const v1: u32 = @intFromEnum(Version.v1);
    buf[offset] = @intCast(v1 >> 24);
    buf[offset + 1] = @intCast((v1 >> 16) & 0xff);
    buf[offset + 2] = @intCast((v1 >> 8) & 0xff);
    buf[offset + 3] = @intCast(v1 & 0xff);
    offset += 4;

    const v2: u32 = @intFromEnum(Version.v2);
    buf[offset] = @intCast(v2 >> 24);
    buf[offset + 1] = @intCast((v2 >> 16) & 0xff);
    buf[offset + 2] = @intCast((v2 >> 8) & 0xff);
    buf[offset + 3] = @intCast(v2 & 0xff);

    return buf;
}

/// 生成 Retry 令牌
pub fn generateRetryToken(
    original_dcid: *const ConnectionId,
    client_addr: []const u8,
    timestamp: u64,
) [64]u8 {
    // 简化实现：实际应使用 AEAD 加密
    var token: [64]u8 = .{0} ** 64;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(original_dcid.id[0..original_dcid.len]);
    hasher.update(client_addr);
    hasher.update(std.mem.asBytes(&timestamp));
    hasher.final(token[0..32]);
    @memcpy(token[32..40], original_dcid.id[0..@min(8, original_dcid.len)]);
    return token;
}

/// 验证 Retry 令牌
pub fn validateRetryToken(
    token: []const u8,
    client_addr: []const u8,
    current_time: u64,
    max_age_sec: u64,
) bool {
    if (token.len != 64) return false;

    // 简化实现：实际应验证 AEAD tag
    _ = client_addr;
    _ = current_time;
    _ = max_age_sec;

    // 检查 token 不全为 0
    for (token) |b| {
        if (b != 0) return true;
    }
    return false;
}

// ============ 单元测试 ============

test "quic module exports" {
    const testing = std.testing;

    // 验证类型导出
    try testing.expect(@TypeOf(Version.v1) == Version);
    try testing.expect(@TypeOf(PacketType.initial) == PacketType);

    // 验证函数导出
    try testing.expect(isVersionSupported(@intFromEnum(Version.v1)));
    try testing.expect(isVersionSupported(@intFromEnum(Version.v2)));
    try testing.expect(!isVersionSupported(0x12345678));
}

test "version negotiation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const dcid = ConnectionId.init(&[_]u8{ 0x01, 0x02, 0x03, 0x04 });
    const scid = ConnectionId.init(&[_]u8{ 0x05, 0x06, 0x07, 0x08 });

    const packet_data = try generateVersionNegotiation(allocator, &dcid, &scid);
    defer allocator.free(packet_data);

    // 验证长包头标志
    try testing.expect((packet_data[0] & 0x80) != 0);
    // 验证版本 = 0
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, packet_data[1..5], .big));
}

test "retry token" {
    const testing = std.testing;

    const dcid = ConnectionId.init(&[_]u8{ 0x01, 0x02, 0x03, 0x04 });
    const token = generateRetryToken(&dcid, "192.168.1.1:12345", 1234567890);

    try testing.expect(token.len == 64);
    try testing.expect(validateRetryToken(&token, "192.168.1.1:12345", 1234567891, 60));
}

// 运行所有子模块测试
test {
    _ = @import("types.zig");
    _ = @import("packet.zig");
    _ = @import("frame.zig");
    _ = @import("tls.zig");
    _ = @import("crypto.zig");
    _ = @import("connection.zig");
    _ = @import("recovery.zig");
    _ = @import("client.zig");
    _ = @import("server.zig");
}
