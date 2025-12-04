//! QUIC 帧格式编解码
//! RFC 9000 Section 19: Frames

const std = @import("std");
const types = @import("types.zig");
const FrameType = types.FrameType;
const StreamId = types.StreamId;
const TransportError = types.TransportError;
const ConnectionId = types.ConnectionId;
const decodeVarInt = types.decodeVarInt;
const encodeVarInt = types.encodeVarInt;
const varIntLen = types.varIntLen;

/// ACK 范围
pub const AckRange = struct {
    /// 最大包号
    largest: u64,
    /// 范围内的包数量 - 1
    count: u64,
};

/// ACK 帧
pub const AckFrame = struct {
    /// 最大确认包号
    largest_acknowledged: u64,
    /// ACK 延迟（微秒）
    ack_delay: u64,
    /// ACK 范围数量
    ack_range_count: u64,
    /// 第一个 ACK 范围
    first_ack_range: u64,
    /// 额外的 ACK 范围（gap, ack_range 对）
    ranges: []const AckRange = &.{},
    /// ECN 计数（仅 ACK_ECN 帧）
    ecn: ?struct {
        ect0: u64,
        ect1: u64,
        ecn_ce: u64,
    } = null,
};

/// CRYPTO 帧
pub const CryptoFrame = struct {
    /// 偏移量
    offset: u64,
    /// 数据
    data: []const u8,
};

/// STREAM 帧
pub const StreamFrame = struct {
    /// 流 ID
    stream_id: StreamId,
    /// 偏移量（可选）
    offset: u64 = 0,
    /// 是否为最后一帧
    fin: bool = false,
    /// 数据
    data: []const u8,
};

/// RESET_STREAM 帧
pub const ResetStreamFrame = struct {
    stream_id: StreamId,
    application_error_code: u62,
    final_size: u64,
};

/// STOP_SENDING 帧
pub const StopSendingFrame = struct {
    stream_id: StreamId,
    application_error_code: u62,
};

/// NEW_TOKEN 帧
pub const NewTokenFrame = struct {
    token: []const u8,
};

/// MAX_DATA 帧
pub const MaxDataFrame = struct {
    maximum_data: u64,
};

/// MAX_STREAM_DATA 帧
pub const MaxStreamDataFrame = struct {
    stream_id: StreamId,
    maximum_stream_data: u64,
};

/// MAX_STREAMS 帧
pub const MaxStreamsFrame = struct {
    bidirectional: bool,
    maximum_streams: u64,
};

/// DATA_BLOCKED 帧
pub const DataBlockedFrame = struct {
    maximum_data: u64,
};

/// STREAM_DATA_BLOCKED 帧
pub const StreamDataBlockedFrame = struct {
    stream_id: StreamId,
    maximum_stream_data: u64,
};

/// STREAMS_BLOCKED 帧
pub const StreamsBlockedFrame = struct {
    bidirectional: bool,
    maximum_streams: u64,
};

/// NEW_CONNECTION_ID 帧
pub const NewConnectionIdFrame = struct {
    sequence_number: u64,
    retire_prior_to: u64,
    connection_id: ConnectionId,
    stateless_reset_token: [16]u8,
};

/// RETIRE_CONNECTION_ID 帧
pub const RetireConnectionIdFrame = struct {
    sequence_number: u64,
};

/// PATH_CHALLENGE 帧
pub const PathChallengeFrame = struct {
    data: [8]u8,
};

/// PATH_RESPONSE 帧
pub const PathResponseFrame = struct {
    data: [8]u8,
};

/// CONNECTION_CLOSE 帧
pub const ConnectionCloseFrame = struct {
    is_application: bool = false,
    error_code: u62,
    frame_type: ?u62 = null, // 仅 transport error
    reason_phrase: []const u8 = "",
};

/// 解析后的帧
pub const Frame = union(enum) {
    padding,
    ping,
    ack: AckFrame,
    crypto: CryptoFrame,
    stream: StreamFrame,
    reset_stream: ResetStreamFrame,
    stop_sending: StopSendingFrame,
    new_token: NewTokenFrame,
    max_data: MaxDataFrame,
    max_stream_data: MaxStreamDataFrame,
    max_streams: MaxStreamsFrame,
    data_blocked: DataBlockedFrame,
    stream_data_blocked: StreamDataBlockedFrame,
    streams_blocked: StreamsBlockedFrame,
    new_connection_id: NewConnectionIdFrame,
    retire_connection_id: RetireConnectionIdFrame,
    path_challenge: PathChallengeFrame,
    path_response: PathResponseFrame,
    connection_close: ConnectionCloseFrame,
    handshake_done,
};

/// 帧解码器
pub const FrameDecoder = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn init(data: []const u8) FrameDecoder {
        return .{ .data = data };
    }

    /// 解码下一帧
    pub fn next(self: *FrameDecoder) !?Frame {
        if (self.pos >= self.data.len) return null;

        const frame_type_result = try decodeVarInt(self.data[self.pos..]);
        const frame_type = frame_type_result.value;
        self.pos += frame_type_result.len;

        // PADDING 帧
        if (frame_type == 0x00) {
            return .padding;
        }

        // PING 帧
        if (frame_type == 0x01) {
            return .ping;
        }

        // ACK 帧
        if (frame_type == 0x02 or frame_type == 0x03) {
            return try self.decodeAck(frame_type == 0x03);
        }

        // CRYPTO 帧
        if (frame_type == 0x06) {
            return try self.decodeCrypto();
        }

        // STREAM 帧 (0x08-0x0f)
        if (frame_type >= 0x08 and frame_type <= 0x0f) {
            return try self.decodeStream(frame_type);
        }

        // RESET_STREAM 帧
        if (frame_type == 0x04) {
            return try self.decodeResetStream();
        }

        // STOP_SENDING 帧
        if (frame_type == 0x05) {
            return try self.decodeStopSending();
        }

        // NEW_TOKEN 帧
        if (frame_type == 0x07) {
            return try self.decodeNewToken();
        }

        // MAX_DATA 帧
        if (frame_type == 0x10) {
            const max_data = try self.readVarInt();
            return Frame{ .max_data = .{ .maximum_data = max_data } };
        }

        // MAX_STREAM_DATA 帧
        if (frame_type == 0x11) {
            const stream_id = try self.readVarInt();
            const max_data = try self.readVarInt();
            return Frame{ .max_stream_data = .{
                .stream_id = StreamId.init(@intCast(stream_id)),
                .maximum_stream_data = max_data,
            } };
        }

        // MAX_STREAMS 帧
        if (frame_type == 0x12 or frame_type == 0x13) {
            const max_streams = try self.readVarInt();
            return Frame{ .max_streams = .{
                .bidirectional = frame_type == 0x12,
                .maximum_streams = max_streams,
            } };
        }

        // DATA_BLOCKED 帧
        if (frame_type == 0x14) {
            const max_data = try self.readVarInt();
            return Frame{ .data_blocked = .{ .maximum_data = max_data } };
        }

        // STREAM_DATA_BLOCKED 帧
        if (frame_type == 0x15) {
            const stream_id = try self.readVarInt();
            const max_data = try self.readVarInt();
            return Frame{ .stream_data_blocked = .{
                .stream_id = StreamId.init(@intCast(stream_id)),
                .maximum_stream_data = max_data,
            } };
        }

        // STREAMS_BLOCKED 帧
        if (frame_type == 0x16 or frame_type == 0x17) {
            const max_streams = try self.readVarInt();
            return Frame{ .streams_blocked = .{
                .bidirectional = frame_type == 0x16,
                .maximum_streams = max_streams,
            } };
        }

        // NEW_CONNECTION_ID 帧
        if (frame_type == 0x18) {
            return try self.decodeNewConnectionId();
        }

        // RETIRE_CONNECTION_ID 帧
        if (frame_type == 0x19) {
            const seq = try self.readVarInt();
            return Frame{ .retire_connection_id = .{ .sequence_number = seq } };
        }

        // PATH_CHALLENGE 帧
        if (frame_type == 0x1a) {
            var data: [8]u8 = undefined;
            try self.readBytes(&data);
            return Frame{ .path_challenge = .{ .data = data } };
        }

        // PATH_RESPONSE 帧
        if (frame_type == 0x1b) {
            var data: [8]u8 = undefined;
            try self.readBytes(&data);
            return Frame{ .path_response = .{ .data = data } };
        }

        // CONNECTION_CLOSE 帧
        if (frame_type == 0x1c or frame_type == 0x1d) {
            return try self.decodeConnectionClose(frame_type == 0x1d);
        }

        // HANDSHAKE_DONE 帧
        if (frame_type == 0x1e) {
            return .handshake_done;
        }

        return error.UnknownFrameType;
    }

    fn decodeAck(self: *FrameDecoder, has_ecn: bool) !Frame {
        const largest_ack = try self.readVarInt();
        const ack_delay = try self.readVarInt();
        const ack_range_count = try self.readVarInt();
        const first_ack_range = try self.readVarInt();

        // TODO: 解析额外的 ACK 范围
        var i: u64 = 0;
        while (i < ack_range_count) : (i += 1) {
            _ = try self.readVarInt(); // gap
            _ = try self.readVarInt(); // ack_range
        }

        var ecn: ?@TypeOf(@as(AckFrame, undefined).ecn) = null;
        if (has_ecn) {
            ecn = .{
                .ect0 = try self.readVarInt(),
                .ect1 = try self.readVarInt(),
                .ecn_ce = try self.readVarInt(),
            };
        }

        return Frame{ .ack = .{
            .largest_acknowledged = largest_ack,
            .ack_delay = ack_delay,
            .ack_range_count = ack_range_count,
            .first_ack_range = first_ack_range,
            .ecn = ecn,
        } };
    }

    fn decodeCrypto(self: *FrameDecoder) !Frame {
        const offset = try self.readVarInt();
        const length = try self.readVarInt();

        if (self.pos + @as(usize, @intCast(length)) > self.data.len) {
            return error.BufferTooShort;
        }

        const data = self.data[self.pos .. self.pos + @as(usize, @intCast(length))];
        self.pos += @intCast(length);

        return Frame{ .crypto = .{
            .offset = offset,
            .data = data,
        } };
    }

    fn decodeStream(self: *FrameDecoder, frame_type: u64) !Frame {
        const flags = FrameType.streamFlags(frame_type);

        const stream_id = try self.readVarInt();
        const offset = if (flags.off) try self.readVarInt() else 0;

        const length = if (flags.len)
            try self.readVarInt()
        else
            self.data.len - self.pos;

        if (self.pos + @as(usize, @intCast(length)) > self.data.len) {
            return error.BufferTooShort;
        }

        const data = self.data[self.pos .. self.pos + @as(usize, @intCast(length))];
        self.pos += @intCast(length);

        return Frame{ .stream = .{
            .stream_id = StreamId.init(@intCast(stream_id)),
            .offset = offset,
            .fin = flags.fin,
            .data = data,
        } };
    }

    fn decodeResetStream(self: *FrameDecoder) !Frame {
        const stream_id = try self.readVarInt();
        const error_code = try self.readVarInt();
        const final_size = try self.readVarInt();

        return Frame{ .reset_stream = .{
            .stream_id = StreamId.init(@intCast(stream_id)),
            .application_error_code = @intCast(error_code),
            .final_size = final_size,
        } };
    }

    fn decodeStopSending(self: *FrameDecoder) !Frame {
        const stream_id = try self.readVarInt();
        const error_code = try self.readVarInt();

        return Frame{ .stop_sending = .{
            .stream_id = StreamId.init(@intCast(stream_id)),
            .application_error_code = @intCast(error_code),
        } };
    }

    fn decodeNewToken(self: *FrameDecoder) !Frame {
        const length = try self.readVarInt();
        if (self.pos + @as(usize, @intCast(length)) > self.data.len) {
            return error.BufferTooShort;
        }

        const token = self.data[self.pos .. self.pos + @as(usize, @intCast(length))];
        self.pos += @intCast(length);

        return Frame{ .new_token = .{ .token = token } };
    }

    fn decodeNewConnectionId(self: *FrameDecoder) !Frame {
        const seq = try self.readVarInt();
        const retire_prior_to = try self.readVarInt();
        const cid_len = try self.readByte();

        if (cid_len > ConnectionId.MAX_CID_LENGTH) return error.InvalidCidLength;

        var cid_data: [ConnectionId.MAX_CID_LENGTH]u8 = undefined;
        try self.readBytes(cid_data[0..cid_len]);

        var reset_token: [16]u8 = undefined;
        try self.readBytes(&reset_token);

        return Frame{ .new_connection_id = .{
            .sequence_number = seq,
            .retire_prior_to = retire_prior_to,
            .connection_id = ConnectionId.init(cid_data[0..cid_len]),
            .stateless_reset_token = reset_token,
        } };
    }

    fn decodeConnectionClose(self: *FrameDecoder, is_app: bool) !Frame {
        const error_code = try self.readVarInt();
        const frame_type = if (!is_app) try self.readVarInt() else null;
        const reason_len = try self.readVarInt();

        if (self.pos + @as(usize, @intCast(reason_len)) > self.data.len) {
            return error.BufferTooShort;
        }

        const reason = self.data[self.pos .. self.pos + @as(usize, @intCast(reason_len))];
        self.pos += @intCast(reason_len);

        return Frame{ .connection_close = .{
            .is_application = is_app,
            .error_code = @intCast(error_code),
            .frame_type = if (frame_type) |ft| @intCast(ft) else null,
            .reason_phrase = reason,
        } };
    }

    fn readVarInt(self: *FrameDecoder) !u64 {
        const result = try decodeVarInt(self.data[self.pos..]);
        self.pos += result.len;
        return result.value;
    }

    fn readByte(self: *FrameDecoder) !u8 {
        if (self.pos >= self.data.len) return error.BufferTooShort;
        const b = self.data[self.pos];
        self.pos += 1;
        return b;
    }

    fn readBytes(self: *FrameDecoder, buf: []u8) !void {
        if (self.pos + buf.len > self.data.len) return error.BufferTooShort;
        @memcpy(buf, self.data[self.pos .. self.pos + buf.len]);
        self.pos += buf.len;
    }
};

/// 帧编码器
pub const FrameEncoder = struct {
    buf: []u8,
    pos: usize = 0,

    pub fn init(buf: []u8) FrameEncoder {
        return .{ .buf = buf };
    }

    /// 获取已编码的数据
    pub fn getWritten(self: *const FrameEncoder) []const u8 {
        return self.buf[0..self.pos];
    }

    /// 编码 PADDING 帧
    pub fn writePadding(self: *FrameEncoder, count: usize) !void {
        if (self.pos + count > self.buf.len) return error.BufferTooShort;
        @memset(self.buf[self.pos .. self.pos + count], 0);
        self.pos += count;
    }

    /// 编码 PING 帧
    pub fn writePing(self: *FrameEncoder) !void {
        try self.writeVarInt(0x01);
    }

    /// 编码 ACK 帧
    pub fn writeAck(self: *FrameEncoder, ack: *const AckFrame) !void {
        try self.writeVarInt(if (ack.ecn != null) 0x03 else 0x02);
        try self.writeVarInt(ack.largest_acknowledged);
        try self.writeVarInt(ack.ack_delay);
        try self.writeVarInt(ack.ack_range_count);
        try self.writeVarInt(ack.first_ack_range);

        for (ack.ranges) |range| {
            try self.writeVarInt(range.largest);
            try self.writeVarInt(range.count);
        }

        if (ack.ecn) |ecn| {
            try self.writeVarInt(ecn.ect0);
            try self.writeVarInt(ecn.ect1);
            try self.writeVarInt(ecn.ecn_ce);
        }
    }

    /// 编码 CRYPTO 帧
    pub fn writeCrypto(self: *FrameEncoder, offset: u64, data: []const u8) !void {
        try self.writeVarInt(0x06);
        try self.writeVarInt(offset);
        try self.writeVarInt(data.len);
        try self.writeBytes(data);
    }

    /// 编码 STREAM 帧
    pub fn writeStream(self: *FrameEncoder, stream: *const StreamFrame) !void {
        var frame_type: u64 = 0x08;
        if (stream.offset > 0) frame_type |= 0x04;
        frame_type |= 0x02; // 总是包含长度
        if (stream.fin) frame_type |= 0x01;

        try self.writeVarInt(frame_type);
        try self.writeVarInt(stream.stream_id.id);
        if (stream.offset > 0) {
            try self.writeVarInt(stream.offset);
        }
        try self.writeVarInt(stream.data.len);
        try self.writeBytes(stream.data);
    }

    /// 编码 CONNECTION_CLOSE 帧
    pub fn writeConnectionClose(self: *FrameEncoder, close: *const ConnectionCloseFrame) !void {
        try self.writeVarInt(if (close.is_application) 0x1d else 0x1c);
        try self.writeVarInt(close.error_code);
        if (!close.is_application) {
            try self.writeVarInt(close.frame_type orelse 0);
        }
        try self.writeVarInt(close.reason_phrase.len);
        try self.writeBytes(close.reason_phrase);
    }

    /// 编码 HANDSHAKE_DONE 帧
    pub fn writeHandshakeDone(self: *FrameEncoder) !void {
        try self.writeVarInt(0x1e);
    }

    /// 编码 MAX_DATA 帧
    pub fn writeMaxData(self: *FrameEncoder, max_data: u64) !void {
        try self.writeVarInt(0x10);
        try self.writeVarInt(max_data);
    }

    /// 编码 MAX_STREAM_DATA 帧
    pub fn writeMaxStreamData(self: *FrameEncoder, stream_id: StreamId, max_data: u64) !void {
        try self.writeVarInt(0x11);
        try self.writeVarInt(stream_id.id);
        try self.writeVarInt(max_data);
    }

    /// 编码 PATH_CHALLENGE 帧
    pub fn writePathChallenge(self: *FrameEncoder, data: *const [8]u8) !void {
        try self.writeVarInt(0x1a);
        try self.writeBytes(data);
    }

    /// 编码 PATH_RESPONSE 帧
    pub fn writePathResponse(self: *FrameEncoder, data: *const [8]u8) !void {
        try self.writeVarInt(0x1b);
        try self.writeBytes(data);
    }

    fn writeVarInt(self: *FrameEncoder, value: u64) !void {
        const len = try encodeVarInt(value, self.buf[self.pos..]);
        self.pos += len;
    }

    fn writeBytes(self: *FrameEncoder, data: []const u8) !void {
        if (self.pos + data.len > self.buf.len) return error.BufferTooShort;
        @memcpy(self.buf[self.pos .. self.pos + data.len], data);
        self.pos += data.len;
    }
};

// ============ 单元测试 ============

test "crypto frame encode/decode" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;

    // 编码
    var encoder = FrameEncoder.init(&buf);
    try encoder.writeCrypto(0, "hello");

    // 解码
    var decoder = FrameDecoder.init(encoder.getWritten());
    const frame = try decoder.next();

    try testing.expect(frame != null);
    const crypto = frame.?.crypto;
    try testing.expectEqual(@as(u64, 0), crypto.offset);
    try testing.expectEqualStrings("hello", crypto.data);
}

test "stream frame encode/decode" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;

    var encoder = FrameEncoder.init(&buf);
    try encoder.writeStream(&.{
        .stream_id = StreamId.init(4),
        .offset = 100,
        .fin = true,
        .data = "world",
    });

    var decoder = FrameDecoder.init(encoder.getWritten());
    const frame = try decoder.next();

    try testing.expect(frame != null);
    const stream = frame.?.stream;
    try testing.expectEqual(@as(u62, 4), stream.stream_id.id);
    try testing.expectEqual(@as(u64, 100), stream.offset);
    try testing.expect(stream.fin);
    try testing.expectEqualStrings("world", stream.data);
}

test "ack frame encode/decode" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;

    var encoder = FrameEncoder.init(&buf);
    try encoder.writeAck(&.{
        .largest_acknowledged = 100,
        .ack_delay = 50,
        .ack_range_count = 0,
        .first_ack_range = 10,
    });

    var decoder = FrameDecoder.init(encoder.getWritten());
    const frame = try decoder.next();

    try testing.expect(frame != null);
    const ack = frame.?.ack;
    try testing.expectEqual(@as(u64, 100), ack.largest_acknowledged);
    try testing.expectEqual(@as(u64, 50), ack.ack_delay);
    try testing.expectEqual(@as(u64, 10), ack.first_ack_range);
}
