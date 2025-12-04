//! QUIC 包格式编解码
//! RFC 9000 Section 17: Packet Formats

const std = @import("std");
const types = @import("types.zig");
const ConnectionId = types.ConnectionId;
const PacketType = types.PacketType;
const Version = types.Version;
const decodeVarInt = types.decodeVarInt;
const encodeVarInt = types.encodeVarInt;
const varIntLen = types.varIntLen;

/// QUIC 包头类型
pub const HeaderForm = enum(u1) {
    short = 0,
    long = 1,
};

/// Long Header 包（用于握手）
pub const LongHeader = struct {
    /// 第一字节的固定位（必须为 1）
    fixed_bit: bool = true,
    /// 包类型
    packet_type: PacketType,
    /// 保留位
    reserved_bits: u2 = 0,
    /// 包号长度 - 1
    packet_number_length: u2,
    /// 版本号
    version: Version,
    /// 目标连接 ID
    dest_cid: ConnectionId,
    /// 源连接 ID
    src_cid: ConnectionId,

    // Initial 包特有字段
    /// Token（仅 Initial 包）
    token: ?[]const u8 = null,
    /// 剩余长度（包号 + 载荷）
    length: u64 = 0,
    /// 包号
    packet_number: u32 = 0,

    /// 解码 Long Header
    pub fn decode(data: []const u8) !struct { header: LongHeader, header_len: usize } {
        if (data.len < 7) return error.BufferTooShort;

        const first_byte = data[0];

        // 检查 Header Form
        if ((first_byte >> 7) != 1) return error.NotLongHeader;

        // 检查 Fixed Bit
        const fixed_bit = ((first_byte >> 6) & 1) == 1;

        // 包类型
        const packet_type: PacketType = @enumFromInt(@as(u2, @truncate(first_byte >> 4)));

        // 保留位和包号长度
        const reserved_bits: u2 = @truncate((first_byte >> 2) & 0x03);
        const pn_length: u2 = @truncate(first_byte & 0x03);

        // 版本号
        const version = Version.fromInt(std.mem.readInt(u32, data[1..5], .big));

        // 目标 CID
        const dcid_len = data[5];
        if (dcid_len > ConnectionId.MAX_CID_LENGTH) return error.InvalidCidLength;
        if (data.len < 6 + dcid_len) return error.BufferTooShort;
        const dest_cid = ConnectionId.init(data[6 .. 6 + dcid_len]);

        // 源 CID
        var offset: usize = 6 + dcid_len;
        if (data.len < offset + 1) return error.BufferTooShort;
        const scid_len = data[offset];
        if (scid_len > ConnectionId.MAX_CID_LENGTH) return error.InvalidCidLength;
        offset += 1;
        if (data.len < offset + scid_len) return error.BufferTooShort;
        const src_cid = ConnectionId.init(data[offset .. offset + scid_len]);
        offset += scid_len;

        var header = LongHeader{
            .fixed_bit = fixed_bit,
            .packet_type = packet_type,
            .reserved_bits = reserved_bits,
            .packet_number_length = pn_length,
            .version = version,
            .dest_cid = dest_cid,
            .src_cid = src_cid,
        };

        // Initial 包有 Token
        if (packet_type == .initial) {
            const token_result = try decodeVarInt(data[offset..]);
            const token_len = token_result.value;
            offset += token_result.len;

            if (data.len < offset + token_len) return error.BufferTooShort;
            if (token_len > 0) {
                header.token = data[offset .. offset + @as(usize, @intCast(token_len))];
            }
            offset += @intCast(token_len);
        }

        // Length 字段
        const length_result = try decodeVarInt(data[offset..]);
        header.length = length_result.value;
        offset += length_result.len;

        // 包号（解密前只能读取加密的包号）
        const pn_len: usize = @as(usize, pn_length) + 1;
        if (data.len < offset + pn_len) return error.BufferTooShort;

        // 包号先设为 0，解密后再设置
        header.packet_number = 0;

        return .{ .header = header, .header_len = offset };
    }

    /// 编码 Long Header
    pub fn encode(self: *const LongHeader, buf: []u8) !usize {
        var offset: usize = 0;

        // First byte
        var first_byte: u8 = 0xc0; // Long header form + fixed bit
        first_byte |= @as(u8, @intFromEnum(self.packet_type)) << 4;
        first_byte |= @as(u8, self.reserved_bits) << 2;
        first_byte |= self.packet_number_length;

        if (buf.len < 1) return error.BufferTooShort;
        buf[offset] = first_byte;
        offset += 1;

        // Version
        if (buf.len < offset + 4) return error.BufferTooShort;
        std.mem.writeInt(u32, buf[offset..][0..4], @intFromEnum(self.version), .big);
        offset += 4;

        // DCID
        if (buf.len < offset + 1 + self.dest_cid.len) return error.BufferTooShort;
        buf[offset] = self.dest_cid.len;
        offset += 1;
        @memcpy(buf[offset .. offset + self.dest_cid.len], self.dest_cid.slice());
        offset += self.dest_cid.len;

        // SCID
        if (buf.len < offset + 1 + self.src_cid.len) return error.BufferTooShort;
        buf[offset] = self.src_cid.len;
        offset += 1;
        @memcpy(buf[offset .. offset + self.src_cid.len], self.src_cid.slice());
        offset += self.src_cid.len;

        // Token (Initial only)
        if (self.packet_type == .initial) {
            const token_len = if (self.token) |t| t.len else 0;
            offset += try encodeVarInt(token_len, buf[offset..]);
            if (token_len > 0) {
                if (buf.len < offset + token_len) return error.BufferTooShort;
                @memcpy(buf[offset .. offset + token_len], self.token.?);
                offset += token_len;
            }
        }

        // Length（这里只是占位，实际值在加密后设置）
        offset += try encodeVarInt(self.length, buf[offset..]);

        // Packet Number（加密前的原始包号）
        const pn_len: usize = @as(usize, self.packet_number_length) + 1;
        if (buf.len < offset + pn_len) return error.BufferTooShort;

        // 写入包号（大端序，变长）
        var pn_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &pn_bytes, self.packet_number, .big);
        @memcpy(buf[offset .. offset + pn_len], pn_bytes[4 - pn_len .. 4]);
        offset += pn_len;

        return offset;
    }
};

/// Short Header 包（用于应用数据）
pub const ShortHeader = struct {
    /// 固定位
    fixed_bit: bool = true,
    /// Spin bit
    spin_bit: bool = false,
    /// 保留位
    reserved_bits: u2 = 0,
    /// Key Phase
    key_phase: bool = false,
    /// 包号长度 - 1
    packet_number_length: u2,
    /// 目标连接 ID
    dest_cid: ConnectionId,
    /// 包号
    packet_number: u32 = 0,

    /// 解码 Short Header
    pub fn decode(data: []const u8, cid_len: u8) !struct { header: ShortHeader, header_len: usize } {
        if (data.len < 1 + cid_len) return error.BufferTooShort;

        const first_byte = data[0];

        // 检查 Header Form
        if ((first_byte >> 7) != 0) return error.NotShortHeader;

        const header = ShortHeader{
            .fixed_bit = ((first_byte >> 6) & 1) == 1,
            .spin_bit = ((first_byte >> 5) & 1) == 1,
            .reserved_bits = @truncate((first_byte >> 3) & 0x03),
            .key_phase = ((first_byte >> 2) & 1) == 1,
            .packet_number_length = @truncate(first_byte & 0x03),
            .dest_cid = ConnectionId.init(data[1 .. 1 + cid_len]),
            .packet_number = 0, // 解密后设置
        };

        return .{ .header = header, .header_len = 1 + cid_len };
    }

    /// 编码 Short Header
    pub fn encode(self: *const ShortHeader, buf: []u8) !usize {
        var offset: usize = 0;

        // First byte
        var first_byte: u8 = 0x40; // Short header form + fixed bit
        if (self.spin_bit) first_byte |= 0x20;
        first_byte |= @as(u8, self.reserved_bits) << 3;
        if (self.key_phase) first_byte |= 0x04;
        first_byte |= self.packet_number_length;

        if (buf.len < 1) return error.BufferTooShort;
        buf[offset] = first_byte;
        offset += 1;

        // DCID
        if (buf.len < offset + self.dest_cid.len) return error.BufferTooShort;
        @memcpy(buf[offset .. offset + self.dest_cid.len], self.dest_cid.slice());
        offset += self.dest_cid.len;

        // Packet Number
        const pn_len: usize = @as(usize, self.packet_number_length) + 1;
        if (buf.len < offset + pn_len) return error.BufferTooShort;

        var pn_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &pn_bytes, self.packet_number, .big);
        @memcpy(buf[offset .. offset + pn_len], pn_bytes[4 - pn_len .. 4]);
        offset += pn_len;

        return offset;
    }
};

/// QUIC 包
pub const Packet = union(enum) {
    long: LongHeader,
    short: ShortHeader,

    /// 判断包类型
    pub fn headerForm(first_byte: u8) HeaderForm {
        return if ((first_byte >> 7) == 1) .long else .short;
    }

    /// 获取目标 CID
    pub fn destCid(self: *const Packet) *const ConnectionId {
        return switch (self.*) {
            .long => |h| &h.dest_cid,
            .short => |h| &h.dest_cid,
        };
    }

    /// 获取包号
    pub fn packetNumber(self: *const Packet) u32 {
        return switch (self.*) {
            .long => |h| h.packet_number,
            .short => |h| h.packet_number,
        };
    }
};

/// 计算完整包号（从截断的包号恢复）
pub fn decodePacketNumber(largest_pn: u64, truncated_pn: u32, pn_len: u2) u64 {
    const pn_nbits: u6 = (@as(u6, pn_len) + 1) * 8;
    const pn_win: u64 = @as(u64, 1) << pn_nbits;
    const pn_hwin: u64 = pn_win / 2;
    const pn_mask: u64 = pn_win - 1;

    // 候选包号
    const candidate_pn = (largest_pn & ~pn_mask) | truncated_pn;

    if (candidate_pn <= largest_pn -| pn_hwin and candidate_pn < (1 << 62) - pn_win) {
        return candidate_pn + pn_win;
    }
    if (candidate_pn > largest_pn + pn_hwin and candidate_pn >= pn_win) {
        return candidate_pn - pn_win;
    }
    return candidate_pn;
}

/// 计算截断包号的长度
pub fn encodePacketNumberLength(pn: u64, largest_acked: u64) u2 {
    const num_unacked = pn -| largest_acked;
    if (num_unacked < (1 << 7)) return 0; // 1 byte
    if (num_unacked < (1 << 15)) return 1; // 2 bytes
    if (num_unacked < (1 << 23)) return 2; // 3 bytes
    return 3; // 4 bytes
}

// ============ 单元测试 ============

test "long header encode/decode" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;

    const header = LongHeader{
        .packet_type = .initial,
        .packet_number_length = 1, // 2 bytes
        .version = .v1,
        .dest_cid = ConnectionId.init(&[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 }),
        .src_cid = ConnectionId.init(&[_]u8{}),
        .token = null,
        .length = 1162,
        .packet_number = 2,
    };

    const len = try header.encode(&buf);
    const result = try LongHeader.decode(buf[0..len]);

    try testing.expectEqual(header.packet_type, result.header.packet_type);
    try testing.expectEqual(header.version, result.header.version);
    try testing.expect(header.dest_cid.eql(&result.header.dest_cid));
    try testing.expect(header.src_cid.eql(&result.header.src_cid));
    try testing.expectEqual(header.length, result.header.length);
}

test "short header encode/decode" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;

    const header = ShortHeader{
        .spin_bit = true,
        .key_phase = false,
        .packet_number_length = 1,
        .dest_cid = ConnectionId.init(&[_]u8{ 0x01, 0x02, 0x03, 0x04 }),
        .packet_number = 0x1234,
    };

    const len = try header.encode(&buf);
    const result = try ShortHeader.decode(buf[0..len], 4);

    try testing.expectEqual(header.spin_bit, result.header.spin_bit);
    try testing.expectEqual(header.key_phase, result.header.key_phase);
    try testing.expect(header.dest_cid.eql(&result.header.dest_cid));
}

test "packet number decode" {
    const testing = std.testing;

    // 示例：largest = 0xa82f30ea, truncated = 0x9b32, len = 1 (2 bytes)
    const result = decodePacketNumber(0xa82f30ea, 0x9b32, 1);
    try testing.expectEqual(@as(u64, 0xa82f9b32), result);
}
