//! QUIC 连接管理
//! 管理连接状态、流、拥塞控制等

const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types.zig");
const packet = @import("packet.zig");
const frame = @import("frame.zig");
const tls = @import("tls.zig");

const ConnectionId = types.ConnectionId;
const Version = types.Version;
const PacketType = types.PacketType;
const StreamId = types.StreamId;
const TransportParameters = types.TransportParameters;
const PacketNumberSpace = types.PacketNumberSpace;
const LongHeader = packet.LongHeader;
const ShortHeader = packet.ShortHeader;
const Frame = frame.Frame;
const FrameDecoder = frame.FrameDecoder;
const FrameEncoder = frame.FrameEncoder;
const Keys = tls.Keys;
const PacketProtector = tls.PacketProtector;

/// 连接状态
pub const ConnectionState = enum {
    /// 等待连接建立
    idle,
    /// 正在握手
    handshaking,
    /// 连接已建立
    connected,
    /// 正在关闭
    closing,
    /// 等待排空
    draining,
    /// 已关闭
    closed,
};

/// 连接角色
pub const Role = enum {
    client,
    server,
};

/// 流状态
pub const StreamState = enum {
    idle,
    open,
    half_closed_local,
    half_closed_remote,
    closed,
};

/// 流
pub const Stream = struct {
    allocator: Allocator,
    id: StreamId,
    state: StreamState = .idle,

    // 发送状态
    send_offset: u64 = 0,
    send_max_data: u64 = 0,
    send_fin: bool = false,

    // 接收状态
    recv_offset: u64 = 0,
    recv_max_data: u64 = 0,
    recv_fin: bool = false,

    // 接收缓冲区
    recv_buffer: std.ArrayListUnmanaged(u8) = .{},

    pub fn init(allocator: Allocator, id: StreamId) Stream {
        return .{
            .allocator = allocator,
            .id = id,
        };
    }

    pub fn deinit(self: *Stream) void {
        self.recv_buffer.deinit(self.allocator);
    }

    /// 写入接收数据
    pub fn writeRecvData(self: *Stream, offset: u64, data: []const u8, fin: bool) !void {
        // 简化实现：假设数据按序到达
        if (offset == self.recv_offset) {
            try self.recv_buffer.appendSlice(self.allocator, data);
            self.recv_offset += data.len;
        }
        if (fin) {
            self.recv_fin = true;
        }
    }

    /// 读取接收数据
    pub fn read(self: *Stream, buf: []u8) usize {
        const len = @min(buf.len, self.recv_buffer.items.len);
        if (len > 0) {
            @memcpy(buf[0..len], self.recv_buffer.items[0..len]);
            // 移除已读数据
            std.mem.copyForwards(
                u8,
                self.recv_buffer.items[0 .. self.recv_buffer.items.len - len],
                self.recv_buffer.items[len..],
            );
            self.recv_buffer.shrinkRetainingCapacity(self.recv_buffer.items.len - len);
        }
        return len;
    }
};

/// 包号空间状态
pub const PacketNumberSpaceState = struct {
    /// 下一个要发送的包号
    next_pn: u64 = 0,
    /// 最大已确认包号
    largest_acked_pn: u64 = 0,
    /// 最大已接收包号
    largest_recv_pn: u64 = 0,
    /// 需要发送 ACK
    ack_eliciting_received: bool = false,

    pub fn getNextPn(self: *PacketNumberSpaceState) u64 {
        const pn = self.next_pn;
        self.next_pn += 1;
        return pn;
    }
};

/// QUIC 连接
pub const Connection = struct {
    allocator: Allocator,

    /// 连接角色
    role: Role,
    /// 连接状态
    state: ConnectionState = .idle,
    /// QUIC 版本
    version: Version = .v1,

    /// 本地连接 ID
    local_cid: ConnectionId,
    /// 远端连接 ID
    remote_cid: ConnectionId,
    /// 原始目标连接 ID（服务端使用）
    original_dcid: ?ConnectionId = null,

    /// 传输参数
    local_params: TransportParameters,
    remote_params: ?TransportParameters = null,

    /// 各包号空间状态
    pn_spaces: [3]PacketNumberSpaceState = .{
        .{}, // Initial
        .{}, // Handshake
        .{}, // Application
    },

    /// 加密密钥
    initial_keys: ?Keys = null,
    handshake_keys: ?Keys = null,
    application_keys: ?Keys = null,

    /// 流管理
    streams: std.AutoHashMap(u62, *Stream),
    next_client_bidi_stream: u62 = 0,
    next_client_uni_stream: u62 = 2,
    next_server_bidi_stream: u62 = 1,
    next_server_uni_stream: u62 = 3,

    /// 流量控制
    max_data: u64 = 0,
    data_sent: u64 = 0,
    max_data_recv: u64 = 0,
    data_recv: u64 = 0,

    /// 发送缓冲区
    send_buffer: std.ArrayListUnmanaged(u8) = .{},
    /// CRYPTO 数据缓冲区
    crypto_send_buffer: [3]std.ArrayListUnmanaged(u8) = .{ .{}, .{}, .{} },
    crypto_recv_buffer: [3]std.ArrayListUnmanaged(u8) = .{ .{}, .{}, .{} },
    crypto_recv_offset: [3]u64 = .{ 0, 0, 0 },

    /// 连接关闭原因
    close_error: ?types.TransportError = null,
    close_reason: []const u8 = "",

    /// 创建客户端连接
    pub fn initClient(allocator: Allocator, params: TransportParameters) !*Connection {
        const conn = try allocator.create(Connection);
        errdefer allocator.destroy(conn);

        // 生成随机连接 ID
        var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
        const random = prng.random();

        conn.* = .{
            .allocator = allocator,
            .role = .client,
            .local_cid = ConnectionId.generate(random),
            .remote_cid = ConnectionId.generate(random), // 临时，收到服务端响应后更新
            .local_params = params,
            .streams = std.AutoHashMap(u62, *Stream).init(allocator),
            .max_data = params.initial_max_data,
        };

        // 派生 Initial 密钥
        conn.initial_keys = Keys.deriveInitial(&conn.remote_cid, conn.version);

        return conn;
    }

    /// 创建服务端连接
    pub fn initServer(allocator: Allocator, params: TransportParameters, dcid: ConnectionId, scid: ConnectionId) !*Connection {
        const conn = try allocator.create(Connection);
        errdefer allocator.destroy(conn);

        var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
        const random = prng.random();

        conn.* = .{
            .allocator = allocator,
            .role = .server,
            .local_cid = ConnectionId.generate(random),
            .remote_cid = scid,
            .original_dcid = dcid,
            .local_params = params,
            .streams = std.AutoHashMap(u62, *Stream).init(allocator),
            .max_data = params.initial_max_data,
        };

        // 使用客户端的 DCID 派生 Initial 密钥
        conn.initial_keys = Keys.deriveInitial(&dcid, conn.version);

        return conn;
    }

    pub fn deinit(self: *Connection) void {
        // 释放流
        var it = self.streams.valueIterator();
        while (it.next()) |stream| {
            stream.*.deinit();
            self.allocator.destroy(stream.*);
        }
        self.streams.deinit();

        // 释放缓冲区
        self.send_buffer.deinit(self.allocator);
        for (&self.crypto_send_buffer) |*buf| {
            buf.deinit(self.allocator);
        }
        for (&self.crypto_recv_buffer) |*buf| {
            buf.deinit(self.allocator);
        }

        self.allocator.destroy(self);
    }

    /// 处理接收到的包
    pub fn receive(self: *Connection, data: []const u8) !void {
        if (data.len == 0) return;

        const header_form = packet.Packet.headerForm(data[0]);

        switch (header_form) {
            .long => try self.receiveLongHeader(data),
            .short => try self.receiveShortHeader(data),
        }
    }

    fn receiveLongHeader(self: *Connection, data: []u8) !void {
        const result = try LongHeader.decode(data);
        const header = result.header;
        const header_len = result.header_len;

        // 验证版本
        if (!header.version.isKnown() and header.version != .negotiation) {
            return error.UnsupportedVersion;
        }

        // 获取对应的密钥
        const keys = switch (header.packet_type) {
            .initial => self.initial_keys,
            .handshake => self.handshake_keys,
            .zero_rtt, .retry => return error.UnsupportedPacketType,
        } orelse return error.KeysNotAvailable;

        const protector = PacketProtector.init(keys);

        // 复制包数据以便修改
        var packet_copy: [2048]u8 = undefined;
        if (data.len > packet_copy.len) return error.PacketTooLarge;
        @memcpy(packet_copy[0..data.len], data);

        // 移除 Header Protection
        const pn_length = try protector.unprotectHeader(
            self.role == .server,
            packet_copy[0..data.len],
            header_len,
        );

        // 读取包号
        const pn_len: usize = @as(usize, pn_length) + 1;
        var pn: u32 = 0;
        for (0..pn_len) |i| {
            pn = (pn << 8) | packet_copy[header_len + i];
        }

        // 计算完整包号
        const space = @intFromEnum(if (header.packet_type == .initial)
            PacketNumberSpace.initial
        else
            PacketNumberSpace.handshake);
        const full_pn = packet.decodePacketNumber(
            self.pn_spaces[space].largest_recv_pn,
            pn,
            pn_length,
        );

        // 解密载荷
        const payload_offset = header_len + pn_len;
        const payload_len = @as(usize, @intCast(header.length)) - pn_len;
        var decrypted: [2048]u8 = undefined;

        const plaintext = try protector.decryptPayload(
            self.role == .server,
            full_pn,
            packet_copy[0..payload_offset],
            packet_copy[payload_offset .. payload_offset + payload_len],
            &decrypted,
        );

        // 更新包号
        if (full_pn > self.pn_spaces[space].largest_recv_pn) {
            self.pn_spaces[space].largest_recv_pn = full_pn;
        }

        // 处理帧
        try self.processFrames(plaintext, header.packet_type);
    }

    fn receiveShortHeader(self: *Connection, data: []u8) !void {
        const result = try ShortHeader.decode(data, self.local_cid.len);
        const header = result.header;
        const header_len = result.header_len;

        const keys = self.application_keys orelse return error.KeysNotAvailable;
        const protector = PacketProtector.init(keys);

        var packet_copy: [2048]u8 = undefined;
        if (data.len > packet_copy.len) return error.PacketTooLarge;
        @memcpy(packet_copy[0..data.len], data);

        const pn_length = try protector.unprotectHeader(
            self.role == .server,
            packet_copy[0..data.len],
            header_len,
        );

        const pn_len: usize = @as(usize, pn_length) + 1;
        var pn: u32 = 0;
        for (0..pn_len) |i| {
            pn = (pn << 8) | packet_copy[header_len + i];
        }

        const full_pn = packet.decodePacketNumber(
            self.pn_spaces[@intFromEnum(PacketNumberSpace.application_data)].largest_recv_pn,
            pn,
            pn_length,
        );

        const payload_offset = header_len + pn_len;
        var decrypted: [2048]u8 = undefined;

        const plaintext = try protector.decryptPayload(
            self.role == .server,
            full_pn,
            packet_copy[0..payload_offset],
            packet_copy[payload_offset..data.len],
            &decrypted,
        );

        if (full_pn > self.pn_spaces[@intFromEnum(PacketNumberSpace.application_data)].largest_recv_pn) {
            self.pn_spaces[@intFromEnum(PacketNumberSpace.application_data)].largest_recv_pn = full_pn;
        }

        _ = header;
        try self.processFrames(plaintext, null);
    }

    fn processFrames(self: *Connection, data: []const u8, packet_type: ?PacketType) !void {
        var decoder = FrameDecoder.init(data);

        while (try decoder.next()) |frm| {
            switch (frm) {
                .padding => {},
                .ping => {
                    // 标记需要发送 ACK
                    const space = if (packet_type) |pt| switch (pt) {
                        .initial => PacketNumberSpace.initial,
                        .handshake => PacketNumberSpace.handshake,
                        else => PacketNumberSpace.application_data,
                    } else PacketNumberSpace.application_data;
                    self.pn_spaces[@intFromEnum(space)].ack_eliciting_received = true;
                },
                .ack => |ack| {
                    try self.processAck(&ack);
                },
                .crypto => |crypto_data| {
                    try self.processCrypto(&crypto_data, packet_type);
                },
                .stream => |stream_data| {
                    try self.processStream(&stream_data);
                },
                .connection_close => |close_frame| {
                    self.close_error = @enumFromInt(close_frame.error_code);
                    self.state = .draining;
                },
                .handshake_done => {
                    if (self.role == .client) {
                        self.state = .connected;
                    }
                },
                .max_data => |md| {
                    if (md.maximum_data > self.max_data) {
                        self.max_data = md.maximum_data;
                    }
                },
                .max_stream_data => |msd| {
                    if (self.streams.get(msd.stream_id.id)) |stream| {
                        if (msd.maximum_stream_data > stream.send_max_data) {
                            stream.send_max_data = msd.maximum_stream_data;
                        }
                    }
                },
                else => {
                    // 其他帧类型暂不处理
                },
            }
        }
    }

    fn processAck(self: *Connection, ack: *const frame.AckFrame) !void {
        // 更新最大已确认包号
        _ = self;
        _ = ack;
        // TODO: 实现 ACK 处理，更新 RTT 估计，触发丢包检测
    }

    fn processCrypto(self: *Connection, crypto_frame: *const frame.CryptoFrame, packet_type: ?PacketType) !void {
        const space: usize = if (packet_type) |pt| switch (pt) {
            .initial => 0,
            .handshake => 1,
            else => 2,
        } else 2;

        // 简化处理：假设数据按序到达
        if (crypto_frame.offset == self.crypto_recv_offset[space]) {
            try self.crypto_recv_buffer[space].appendSlice(self.allocator, crypto_frame.data);
            self.crypto_recv_offset[space] += crypto_frame.data.len;

            // TODO: 将 CRYPTO 数据传给 TLS 状态机
        }
    }

    fn processStream(self: *Connection, stream_frame: *const frame.StreamFrame) !void {
        // 获取或创建流
        var stream = self.streams.get(stream_frame.stream_id.id);
        if (stream == null) {
            const new_stream = try self.allocator.create(Stream);
            new_stream.* = Stream.init(self.allocator, stream_frame.stream_id);
            try self.streams.put(stream_frame.stream_id.id, new_stream);
            stream = new_stream;
        }

        // 写入数据
        try stream.?.writeRecvData(stream_frame.offset, stream_frame.data, stream_frame.fin);
    }

    /// 创建新的双向流
    pub fn openBidiStream(self: *Connection) !StreamId {
        const id = if (self.role == .client) blk: {
            const id = self.next_client_bidi_stream;
            self.next_client_bidi_stream += 4;
            break :blk id;
        } else blk: {
            const id = self.next_server_bidi_stream;
            self.next_server_bidi_stream += 4;
            break :blk id;
        };

        const stream_id = StreamId.init(id);
        const stream = try self.allocator.create(Stream);
        stream.* = Stream.init(self.allocator, stream_id);
        try self.streams.put(id, stream);

        return stream_id;
    }

    /// 发送流数据
    pub fn sendStreamData(self: *Connection, stream_id: StreamId, data: []const u8, fin: bool) !void {
        const stream = self.streams.get(stream_id.id) orelse return error.StreamNotFound;

        // 构建 STREAM 帧并加入发送队列
        var frame_buf: [2048]u8 = undefined;
        var encoder = FrameEncoder.init(&frame_buf);
        try encoder.writeStream(&.{
            .stream_id = stream_id,
            .offset = stream.send_offset,
            .fin = fin,
            .data = data,
        });

        stream.send_offset += data.len;
        if (fin) stream.send_fin = true;

        try self.send_buffer.appendSlice(self.allocator, encoder.getWritten());
    }

    /// 生成要发送的包
    pub fn generatePacket(self: *Connection, buf: []u8) !?usize {
        if (self.send_buffer.items.len == 0) return null;

        // 简化实现：生成 1-RTT 包
        const keys = self.application_keys orelse self.initial_keys orelse return null;
        const protector = PacketProtector.init(keys);

        const pn = self.pn_spaces[@intFromEnum(PacketNumberSpace.application_data)].getNextPn();
        const pn_length = packet.encodePacketNumberLength(pn, self.pn_spaces[@intFromEnum(PacketNumberSpace.application_data)].largest_acked_pn);

        // 构建包头
        var header: ShortHeader = .{
            .packet_number_length = pn_length,
            .dest_cid = self.remote_cid,
            .packet_number = @intCast(pn),
        };

        const header_len = try header.encode(buf);

        // 载荷大小
        const max_payload = @min(self.send_buffer.items.len, buf.len - header_len - 16); // 16 = AEAD tag
        const payload = self.send_buffer.items[0..max_payload];

        // 加密载荷
        var encrypted_payload: [2048]u8 = undefined;
        const encrypted = try protector.encryptPayload(
            self.role == .server,
            pn,
            buf[0..header_len],
            payload,
            &encrypted_payload,
        );

        @memcpy(buf[header_len .. header_len + encrypted.len], encrypted);
        const total_len = header_len + encrypted.len;

        // 应用 Header Protection
        protector.protectHeader(
            self.role == .server,
            buf[0..total_len],
            header_len - @as(usize, pn_length) - 1,
            @as(usize, pn_length) + 1,
        );

        // 移除已发送的数据
        std.mem.copyForwards(
            u8,
            self.send_buffer.items[0 .. self.send_buffer.items.len - max_payload],
            self.send_buffer.items[max_payload..],
        );
        self.send_buffer.shrinkRetainingCapacity(self.send_buffer.items.len - max_payload);

        return total_len;
    }

    /// 关闭连接
    pub fn close(self: *Connection, error_code: types.TransportError, reason: []const u8) !void {
        self.close_error = error_code;
        self.close_reason = reason;
        self.state = .closing;

        // 构建 CONNECTION_CLOSE 帧
        var frame_buf: [256]u8 = undefined;
        var encoder = FrameEncoder.init(&frame_buf);
        try encoder.writeConnectionClose(&.{
            .is_application = false,
            .error_code = @intFromEnum(error_code),
            .frame_type = null,
            .reason_phrase = reason,
        });

        try self.send_buffer.appendSlice(self.allocator, encoder.getWritten());
    }
};

// ============ 单元测试 ============

test "connection init client" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const conn = try Connection.initClient(allocator, TransportParameters.defaultClient());
    defer conn.deinit();

    try testing.expectEqual(Role.client, conn.role);
    try testing.expectEqual(ConnectionState.idle, conn.state);
    try testing.expect(conn.initial_keys != null);
}

test "connection init server" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const dcid = ConnectionId.init(&[_]u8{ 0x01, 0x02, 0x03, 0x04 });
    const scid = ConnectionId.init(&[_]u8{ 0x05, 0x06, 0x07, 0x08 });

    const conn = try Connection.initServer(allocator, TransportParameters.defaultServer(), dcid, scid);
    defer conn.deinit();

    try testing.expectEqual(Role.server, conn.role);
    try testing.expect(conn.original_dcid != null);
}

test "stream management" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const conn = try Connection.initClient(allocator, TransportParameters.defaultClient());
    defer conn.deinit();

    // 创建流
    const stream_id = try conn.openBidiStream();
    try testing.expectEqual(@as(u62, 0), stream_id.id); // 客户端双向流从 0 开始
    try testing.expect(stream_id.isClientInitiated());
    try testing.expect(stream_id.isBidirectional());
}
