//! QUIC 协议基础类型定义
//! RFC 9000: https://www.rfc-editor.org/rfc/rfc9000.html

const std = @import("std");

/// QUIC 版本号
pub const Version = enum(u32) {
    /// Version Negotiation 专用
    negotiation = 0x00000000,
    /// QUIC v1 (RFC 9000)
    v1 = 0x00000001,
    /// QUIC v2 (RFC 9369)
    v2 = 0x6b3343cf,

    /// 检查是否为已知版本
    pub fn isKnown(self: Version) bool {
        return switch (self) {
            .v1, .v2 => true,
            else => false,
        };
    }

    pub fn fromInt(value: u32) Version {
        return @enumFromInt(value);
    }
};

/// QUIC 包类型 (Long Header)
pub const PacketType = enum(u2) {
    initial = 0,
    zero_rtt = 1,
    handshake = 2,
    retry = 3,
};

/// 连接 ID（最大 20 字节）
pub const ConnectionId = struct {
    id: [MAX_CID_LENGTH]u8 = undefined,
    len: u8 = 0,

    pub const MAX_CID_LENGTH = 20;

    pub fn init(bytes: []const u8) ConnectionId {
        var cid = ConnectionId{};
        cid.len = @intCast(@min(bytes.len, MAX_CID_LENGTH));
        @memcpy(cid.id[0..cid.len], bytes[0..cid.len]);
        return cid;
    }

    pub fn generate(random: std.Random) ConnectionId {
        var cid = ConnectionId{ .len = 8 }; // 默认 8 字节
        random.bytes(cid.id[0..cid.len]);
        return cid;
    }

    pub fn slice(self: *const ConnectionId) []const u8 {
        return self.id[0..self.len];
    }

    pub fn eql(self: *const ConnectionId, other: *const ConnectionId) bool {
        if (self.len != other.len) return false;
        return std.mem.eql(u8, self.id[0..self.len], other.id[0..other.len]);
    }

    pub fn isEmpty(self: *const ConnectionId) bool {
        return self.len == 0;
    }
};

/// 包号空间
pub const PacketNumberSpace = enum(u2) {
    initial = 0,
    handshake = 1,
    application_data = 2,
};

/// 传输错误码 (RFC 9000 Section 20.1)
pub const TransportError = enum(u62) {
    no_error = 0x00,
    internal_error = 0x01,
    connection_refused = 0x02,
    flow_control_error = 0x03,
    stream_limit_error = 0x04,
    stream_state_error = 0x05,
    final_size_error = 0x06,
    frame_encoding_error = 0x07,
    transport_parameter_error = 0x08,
    connection_id_limit_error = 0x09,
    protocol_violation = 0x0a,
    invalid_token = 0x0b,
    application_error = 0x0c,
    crypto_buffer_exceeded = 0x0d,
    key_update_error = 0x0e,
    aead_limit_reached = 0x0f,
    no_viable_path = 0x10,
    // 0x0100-0x01ff: CRYPTO_ERROR
    crypto_error_base = 0x0100,

    pub fn cryptoError(alert: u8) TransportError {
        return @enumFromInt(@as(u62, 0x0100) | @as(u62, alert));
    }
};

/// 帧类型 (RFC 9000 Section 12.4)
pub const FrameType = enum(u62) {
    padding = 0x00,
    ping = 0x01,
    ack = 0x02,
    ack_ecn = 0x03,
    reset_stream = 0x04,
    stop_sending = 0x05,
    crypto = 0x06,
    new_token = 0x07,
    stream = 0x08, // 0x08-0x0f
    stream_fin = 0x09,
    stream_len = 0x0a,
    stream_len_fin = 0x0b,
    stream_off = 0x0c,
    stream_off_fin = 0x0d,
    stream_off_len = 0x0e,
    stream_off_len_fin = 0x0f,
    max_data = 0x10,
    max_stream_data = 0x11,
    max_streams_bidi = 0x12,
    max_streams_uni = 0x13,
    data_blocked = 0x14,
    stream_data_blocked = 0x15,
    streams_blocked_bidi = 0x16,
    streams_blocked_uni = 0x17,
    new_connection_id = 0x18,
    retire_connection_id = 0x19,
    path_challenge = 0x1a,
    path_response = 0x1b,
    connection_close = 0x1c,
    connection_close_app = 0x1d,
    handshake_done = 0x1e,

    /// 检查是否为 STREAM 帧（0x08-0x0f）
    pub fn isStream(frame_type: u62) bool {
        return (frame_type >= 0x08 and frame_type <= 0x0f);
    }

    /// 从 STREAM 帧类型解析标志位
    pub fn streamFlags(frame_type: u62) struct { off: bool, len: bool, fin: bool } {
        return .{
            .off = (frame_type & 0x04) != 0,
            .len = (frame_type & 0x02) != 0,
            .fin = (frame_type & 0x01) != 0,
        };
    }
};

/// 传输参数 ID (RFC 9000 Section 18.2)
pub const TransportParameterId = enum(u62) {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    max_udp_payload_size = 0x03,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    ack_delay_exponent = 0x0a,
    max_ack_delay = 0x0b,
    disable_active_migration = 0x0c,
    preferred_address = 0x0d,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    retry_source_connection_id = 0x10,
    // QUIC v2
    version_information = 0x11,
    // 扩展
    max_datagram_frame_size = 0x20,
    grease_quic_bit = 0x2ab2,
};

/// 传输参数
pub const TransportParameters = struct {
    original_destination_connection_id: ?ConnectionId = null,
    max_idle_timeout: u64 = 0, // ms, 0 = disabled
    stateless_reset_token: ?[16]u8 = null,
    max_udp_payload_size: u64 = 65527,
    initial_max_data: u64 = 0,
    initial_max_stream_data_bidi_local: u64 = 0,
    initial_max_stream_data_bidi_remote: u64 = 0,
    initial_max_stream_data_uni: u64 = 0,
    initial_max_streams_bidi: u64 = 0,
    initial_max_streams_uni: u64 = 0,
    ack_delay_exponent: u64 = 3, // default
    max_ack_delay: u64 = 25, // ms, default
    disable_active_migration: bool = false,
    active_connection_id_limit: u64 = 2, // default
    initial_source_connection_id: ?ConnectionId = null,
    retry_source_connection_id: ?ConnectionId = null,

    /// 创建默认客户端参数
    pub fn defaultClient() TransportParameters {
        return .{
            .max_idle_timeout = 30000, // 30s
            .max_udp_payload_size = 1350,
            .initial_max_data = 1024 * 1024, // 1MB
            .initial_max_stream_data_bidi_local = 256 * 1024,
            .initial_max_stream_data_bidi_remote = 256 * 1024,
            .initial_max_stream_data_uni = 256 * 1024,
            .initial_max_streams_bidi = 100,
            .initial_max_streams_uni = 100,
            .active_connection_id_limit = 8,
        };
    }

    /// 创建默认服务端参数
    pub fn defaultServer() TransportParameters {
        return .{
            .max_idle_timeout = 30000,
            .max_udp_payload_size = 1350,
            .initial_max_data = 1024 * 1024,
            .initial_max_stream_data_bidi_local = 256 * 1024,
            .initial_max_stream_data_bidi_remote = 256 * 1024,
            .initial_max_stream_data_uni = 256 * 1024,
            .initial_max_streams_bidi = 100,
            .initial_max_streams_uni = 100,
            .active_connection_id_limit = 8,
        };
    }
};

/// 流 ID
pub const StreamId = struct {
    id: u62,

    /// 流类型
    pub const Type = enum(u2) {
        client_bidi = 0,
        server_bidi = 1,
        client_uni = 2,
        server_uni = 3,
    };

    pub fn init(id: u62) StreamId {
        return .{ .id = id };
    }

    /// 获取流类型
    pub fn getType(self: StreamId) Type {
        return @enumFromInt(@as(u2, @truncate(self.id)));
    }

    /// 是否为客户端发起
    pub fn isClientInitiated(self: StreamId) bool {
        return (self.id & 1) == 0;
    }

    /// 是否为双向流
    pub fn isBidirectional(self: StreamId) bool {
        return (self.id & 2) == 0;
    }

    /// 创建下一个客户端双向流 ID
    pub fn nextClientBidi(current_max: u62) StreamId {
        return .{ .id = (current_max + 4) & ~@as(u62, 3) };
    }

    /// 创建下一个客户端单向流 ID
    pub fn nextClientUni(current_max: u62) StreamId {
        return .{ .id = ((current_max + 4) & ~@as(u62, 3)) | 2 };
    }
};

// ============ 变长整数编解码 (RFC 9000 Section 16) ============

/// 变长整数前缀
pub const VarIntPrefix = enum(u2) {
    one_byte = 0, // 6-bit value, max 63
    two_byte = 1, // 14-bit value, max 16383
    four_byte = 2, // 30-bit value, max 1073741823
    eight_byte = 3, // 62-bit value, max 4611686018427387903
};

/// 变长整数最大值
pub const VARINT_MAX: u64 = (1 << 62) - 1;

/// 解码变长整数
pub fn decodeVarInt(data: []const u8) error{BufferTooShort}!struct { value: u64, len: usize } {
    if (data.len == 0) return error.BufferTooShort;

    const prefix: VarIntPrefix = @enumFromInt(@as(u2, @truncate(data[0] >> 6)));
    const needed = @as(usize, 1) << @intFromEnum(prefix);

    if (data.len < needed) return error.BufferTooShort;

    var value: u64 = data[0] & 0x3f;
    for (1..needed) |i| {
        value = (value << 8) | data[i];
    }

    return .{ .value = value, .len = needed };
}

/// 编码变长整数
pub fn encodeVarInt(value: u64, buf: []u8) error{BufferTooShort}!usize {
    if (value <= 63) {
        if (buf.len < 1) return error.BufferTooShort;
        buf[0] = @truncate(value);
        return 1;
    } else if (value <= 16383) {
        if (buf.len < 2) return error.BufferTooShort;
        buf[0] = @truncate((value >> 8) | 0x40);
        buf[1] = @truncate(value);
        return 2;
    } else if (value <= 1073741823) {
        if (buf.len < 4) return error.BufferTooShort;
        buf[0] = @truncate((value >> 24) | 0x80);
        buf[1] = @truncate(value >> 16);
        buf[2] = @truncate(value >> 8);
        buf[3] = @truncate(value);
        return 4;
    } else if (value <= VARINT_MAX) {
        if (buf.len < 8) return error.BufferTooShort;
        buf[0] = @truncate((value >> 56) | 0xc0);
        buf[1] = @truncate(value >> 48);
        buf[2] = @truncate(value >> 40);
        buf[3] = @truncate(value >> 32);
        buf[4] = @truncate(value >> 24);
        buf[5] = @truncate(value >> 16);
        buf[6] = @truncate(value >> 8);
        buf[7] = @truncate(value);
        return 8;
    } else {
        unreachable; // value > VARINT_MAX
    }
}

/// 计算变长整数编码所需字节数
pub fn varIntLen(value: u64) usize {
    if (value <= 63) return 1;
    if (value <= 16383) return 2;
    if (value <= 1073741823) return 4;
    return 8;
}

// ============ 单元测试 ============

test "varint encoding/decoding" {
    const testing = std.testing;
    var buf: [8]u8 = undefined;

    // 1 字节
    {
        const len = try encodeVarInt(37, &buf);
        try testing.expectEqual(@as(usize, 1), len);
        try testing.expectEqual(@as(u8, 0x25), buf[0]);

        const result = try decodeVarInt(buf[0..len]);
        try testing.expectEqual(@as(u64, 37), result.value);
        try testing.expectEqual(@as(usize, 1), result.len);
    }

    // 2 字节
    {
        const len = try encodeVarInt(15293, &buf);
        try testing.expectEqual(@as(usize, 2), len);

        const result = try decodeVarInt(buf[0..len]);
        try testing.expectEqual(@as(u64, 15293), result.value);
    }

    // 4 字节
    {
        const len = try encodeVarInt(494878333, &buf);
        try testing.expectEqual(@as(usize, 4), len);

        const result = try decodeVarInt(buf[0..len]);
        try testing.expectEqual(@as(u64, 494878333), result.value);
    }

    // 8 字节
    {
        const len = try encodeVarInt(151288809941952652, &buf);
        try testing.expectEqual(@as(usize, 8), len);

        const result = try decodeVarInt(buf[0..len]);
        try testing.expectEqual(@as(u64, 151288809941952652), result.value);
    }
}

test "connection id" {
    const testing = std.testing;

    const cid1 = ConnectionId.init(&[_]u8{ 0x01, 0x02, 0x03, 0x04 });
    try testing.expectEqual(@as(u8, 4), cid1.len);

    var cid2 = ConnectionId.init(&[_]u8{ 0x01, 0x02, 0x03, 0x04 });
    try testing.expect(cid1.eql(&cid2));

    cid2.id[0] = 0xff;
    try testing.expect(!cid1.eql(&cid2));
}

test "stream id" {
    const testing = std.testing;

    const client_bidi = StreamId.init(0);
    try testing.expect(client_bidi.isClientInitiated());
    try testing.expect(client_bidi.isBidirectional());
    try testing.expectEqual(StreamId.Type.client_bidi, client_bidi.getType());

    const server_uni = StreamId.init(3);
    try testing.expect(!server_uni.isClientInitiated());
    try testing.expect(!server_uni.isBidirectional());
    try testing.expectEqual(StreamId.Type.server_uni, server_uni.getType());
}
