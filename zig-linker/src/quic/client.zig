//! QUIC 客户端实现
//! 提供简洁的客户端 API 用于连接 QUIC 服务器

const std = @import("std");
const Allocator = std.mem.Allocator;
const net = std.net;
const posix = std.posix;

const types = @import("types.zig");
const packet = @import("packet.zig");
const frame = @import("frame.zig");
const tls = @import("tls.zig");
const crypto = @import("crypto.zig");
const connection = @import("connection.zig");
const recovery = @import("recovery.zig");

const Connection = connection.Connection;
const ConnectionState = connection.ConnectionState;
const Role = connection.Role;
const CryptoContext = crypto.CryptoContext;
const HandshakeState = crypto.HandshakeState;
const Keys = tls.Keys;
const PacketProtector = tls.PacketProtector;

/// 客户端配置
pub const ClientConfig = struct {
    /// 服务器地址
    server_address: net.Address,
    /// 服务器名称（SNI）
    server_name: ?[]const u8 = null,
    /// ALPN 协议列表
    alpn: ?[]const u8 = null,
    /// 传输参数
    transport_params: ?types.TransportParameters = null,
    /// 连接超时（毫秒）
    connect_timeout_ms: u64 = 10000,
    /// 空闲超时（毫秒）
    idle_timeout_ms: u64 = 30000,
    /// 是否验证服务器证书
    verify_certificate: bool = true,
};

/// 客户端事件
pub const ClientEvent = union(enum) {
    /// 连接建立
    connected,
    /// 收到数据
    data_received: struct {
        stream_id: u64,
        data: []const u8,
        fin: bool,
    },
    /// 流已关闭
    stream_closed: u64,
    /// 连接关闭
    connection_closed: struct {
        error_code: u64,
        reason: []const u8,
    },
    /// 握手完成
    handshake_completed,
    /// 需要发送数据
    send_required,
};

/// QUIC 客户端
pub const QuicClient = struct {
    allocator: Allocator,
    config: ClientConfig,

    /// UDP Socket
    socket: ?posix.socket_t = null,

    /// QUIC 连接
    conn: ?Connection = null,

    /// 加密上下文
    crypto_ctx: ?CryptoContext = null,

    /// 密钥
    initial_keys: ?struct { client: Keys, server: Keys } = null,
    handshake_keys: ?struct { client: Keys, server: Keys } = null,
    app_keys: ?struct { client: Keys, server: Keys } = null,

    /// 数据包保护器
    initial_protector: ?PacketProtector = null,
    handshake_protector: ?PacketProtector = null,
    app_protector: ?PacketProtector = null,

    /// 发送/接收缓冲区
    send_buffer: [65536]u8 = undefined,
    recv_buffer: [65536]u8 = undefined,

    /// 包号
    next_packet_number: u64 = 0,

    /// 连接 ID
    src_conn_id: types.ConnectionId = undefined,
    dst_conn_id: types.ConnectionId = undefined,

    /// 是否已连接
    connected: bool = false,

    /// 丢包恢复
    loss_detector: ?recovery.LossDetector = null,

    pub fn init(allocator: Allocator, config: ClientConfig) QuicClient {
        var client = QuicClient{
            .allocator = allocator,
            .config = config,
        };

        // 生成源连接 ID
        var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
        const random = prng.random();
        client.src_conn_id.len = 8;
        random.bytes(client.src_conn_id.id[0..8]);

        // 初始目标连接 ID（用于 Initial 包）
        client.dst_conn_id.len = 8;
        random.bytes(client.dst_conn_id.id[0..8]);

        return client;
    }

    pub fn deinit(self: *QuicClient) void {
        if (self.socket) |sock| {
            posix.close(sock);
            self.socket = null;
        }

        if (self.conn) |*c| {
            c.deinit();
            self.conn = null;
        }

        if (self.crypto_ctx) |*ctx| {
            ctx.deinit();
            self.crypto_ctx = null;
        }

        if (self.loss_detector) |*ld| {
            ld.deinit();
            self.loss_detector = null;
        }
    }

    /// 连接到服务器
    pub fn connect(self: *QuicClient) !void {
        // 创建 UDP socket
        const addr_family: posix.sa_family_t = switch (self.config.server_address.any.family) {
            posix.AF.INET => posix.AF.INET,
            posix.AF.INET6 => posix.AF.INET6,
            else => return error.UnsupportedAddressFamily,
        };

        self.socket = try posix.socket(addr_family, posix.SOCK.DGRAM, 0);
        errdefer {
            if (self.socket) |sock| posix.close(sock);
            self.socket = null;
        }

        // 设置非阻塞
        // 注意：Windows 上需要使用不同的方式
        if (@import("builtin").os.tag != .windows) {
            const flags = try posix.fcntl(self.socket.?, posix.F.GETFL, 0);
            _ = try posix.fcntl(self.socket.?, posix.F.SETFL, @as(u32, @bitCast(flags)) | @as(u32, @intFromEnum(posix.O.NONBLOCK)));
        }

        // 初始化加密上下文
        self.crypto_ctx = CryptoContext.init(self.allocator, .client);
        if (self.config.alpn) |alpn| {
            self.crypto_ctx.?.alpn = alpn;
        }
        if (self.config.transport_params) |params| {
            self.crypto_ctx.?.local_transport_params = params;
        } else {
            self.crypto_ctx.?.local_transport_params = types.TransportParameters.defaultClient();
        }

        // 初始化连接
        self.conn = Connection.init(self.allocator, .client);
        self.conn.?.src_conn_id = self.src_conn_id;
        self.conn.?.dst_conn_id = self.dst_conn_id;

        // 初始化丢包检测
        self.loss_detector = recovery.LossDetector.init(self.allocator);

        // 派生 Initial 密钥
        const initial_keys = Keys.deriveInitial(&self.dst_conn_id);
        self.initial_keys = .{ .client = initial_keys.client, .server = initial_keys.server };
        self.initial_protector = PacketProtector.init(&initial_keys.client);

        // 发送 Initial 包（包含 ClientHello）
        try self.sendInitial();
    }

    /// 发送 Initial 包
    fn sendInitial(self: *QuicClient) !void {
        var buf = &self.send_buffer;

        // 构造 CRYPTO 帧（包含 ClientHello）
        var crypto_data: [512]u8 = undefined;
        const crypto_len = try self.crypto_ctx.?.generateClientHello(&crypto_data);

        // 构造 Initial 包
        var payload_buf: [1200]u8 = undefined;
        var payload_offset: usize = 0;

        // CRYPTO 帧
        const crypto_frame = frame.Frame{ .crypto = .{
            .offset = 0,
            .data = crypto_data[0..crypto_len],
        } };
        payload_offset += frame.FrameEncoder.encode(crypto_frame, payload_buf[payload_offset..]);

        // 添加 PADDING 帧（Initial 包需要至少 1200 字节）
        const min_size = 1200;
        const header_size = 50; // 大约的头部大小
        const crypto_overhead = 16; // AEAD tag
        while (payload_offset + header_size + crypto_overhead < min_size) {
            payload_buf[payload_offset] = 0x00; // PADDING
            payload_offset += 1;
        }

        // 构造 Long Header
        const pn = self.next_packet_number;
        self.next_packet_number += 1;

        var offset: usize = 0;

        // 第一字节：Long Header, Initial, 4-byte PN
        buf[offset] = 0xc0 | 0x00 | 0x03; // Form=1, Fixed=1, Type=Initial, PN Len=4
        offset += 1;

        // Version
        buf[offset] = 0x00;
        buf[offset + 1] = 0x00;
        buf[offset + 2] = 0x00;
        buf[offset + 3] = 0x01; // Version 1
        offset += 4;

        // Dest Conn ID
        buf[offset] = self.dst_conn_id.len;
        offset += 1;
        @memcpy(buf[offset .. offset + self.dst_conn_id.len], self.dst_conn_id.id[0..self.dst_conn_id.len]);
        offset += self.dst_conn_id.len;

        // Src Conn ID
        buf[offset] = self.src_conn_id.len;
        offset += 1;
        @memcpy(buf[offset .. offset + self.src_conn_id.len], self.src_conn_id.id[0..self.src_conn_id.len]);
        offset += self.src_conn_id.len;

        // Token (empty for client Initial)
        buf[offset] = 0;
        offset += 1;

        // Length (变长整数，包含 PN + payload + tag)
        const packet_number_len: usize = 4;
        const total_len = packet_number_len + payload_offset + 16; // 16 = AEAD tag
        offset += types.encodeVarInt(buf[offset..], total_len);

        // Packet Number（明文，后续会被保护）
        const pn_offset = offset;
        buf[offset] = @intCast((pn >> 24) & 0xff);
        buf[offset + 1] = @intCast((pn >> 16) & 0xff);
        buf[offset + 2] = @intCast((pn >> 8) & 0xff);
        buf[offset + 3] = @intCast(pn & 0xff);
        offset += 4;

        // Payload（明文）
        const payload_start = offset;
        @memcpy(buf[offset .. offset + payload_offset], payload_buf[0..payload_offset]);
        offset += payload_offset;

        // 加密 payload
        if (self.initial_protector) |*protector| {
            const encrypted_len = protector.encrypt(
                pn,
                buf[0..pn_offset],
                buf[payload_start .. payload_start + payload_offset],
                buf[payload_start..],
            ) catch payload_offset;
            offset = payload_start + encrypted_len;

            // 应用头部保护
            protector.protectHeader(buf, pn_offset, 4);
        }

        // 发送
        _ = try posix.sendto(self.socket.?, buf[0..offset], 0, &self.config.server_address.any, self.config.server_address.getOsSockLen());

        // 记录发送的包
        if (self.loss_detector) |*ld| {
            ld.onPacketSent(pn, offset, true);
        }
    }

    /// 处理收到的数据包
    pub fn processPacket(self: *QuicClient, data: []const u8) !?ClientEvent {
        if (data.len < 1) return null;

        const first_byte = data[0];
        const is_long = (first_byte & 0x80) != 0;

        if (is_long) {
            return try self.processLongHeaderPacket(data);
        } else {
            return try self.processShortHeaderPacket(data);
        }
    }

    /// 处理 Long Header 包
    fn processLongHeaderPacket(self: *QuicClient, data: []const u8) !?ClientEvent {
        if (data.len < 7) return error.PacketTooShort;

        const first_byte = data[0];
        const packet_type = (first_byte >> 4) & 0x03;

        // 解析头部
        var offset: usize = 1;

        // Version
        const version = (@as(u32, data[offset]) << 24) |
            (@as(u32, data[offset + 1]) << 16) |
            (@as(u32, data[offset + 2]) << 8) |
            data[offset + 3];
        offset += 4;

        if (version == 0) {
            // Version Negotiation
            return error.VersionNegotiation;
        }

        // Dest Conn ID
        const dcid_len = data[offset];
        offset += 1;
        if (offset + dcid_len > data.len) return error.PacketTooShort;
        offset += dcid_len;

        // Src Conn ID
        const scid_len = data[offset];
        offset += 1;
        if (offset + scid_len > data.len) return error.PacketTooShort;

        // 更新目标连接 ID
        if (scid_len > 0 and scid_len <= 20) {
            self.dst_conn_id.len = scid_len;
            @memcpy(self.dst_conn_id.id[0..scid_len], data[offset .. offset + scid_len]);
        }
        offset += scid_len;

        switch (packet_type) {
            0x00 => return try self.processInitialPacket(data, offset),
            0x02 => return try self.processHandshakePacket(data, offset),
            else => return null,
        }
    }

    /// 处理 Initial 包
    fn processInitialPacket(self: *QuicClient, data: []const u8, start_offset: usize) !?ClientEvent {
        var offset = start_offset;

        // Token Length (for Retry)
        const token_len_result = types.decodeVarInt(data[offset..]);
        offset += token_len_result.len;
        offset += @intCast(token_len_result.value); // Skip token

        // Length
        const length_result = types.decodeVarInt(data[offset..]);
        offset += length_result.len;
        const payload_len: usize = @intCast(length_result.value);

        if (offset + payload_len > data.len) return error.PacketTooShort;

        // 使用服务端的 Initial 密钥解密
        const server_keys = if (self.initial_keys) |k| k.server else return error.NoKeys;
        var protector = PacketProtector.init(&server_keys);

        // 解除头部保护
        var packet_buf: [65536]u8 = undefined;
        @memcpy(packet_buf[0..data.len], data);

        const pn_offset = offset;
        protector.unprotectHeader(&packet_buf, pn_offset, data.len);

        // 获取包号长度和包号
        const pn_len: usize = (packet_buf[0] & 0x03) + 1;
        var pn: u64 = 0;
        for (0..pn_len) |i| {
            pn = (pn << 8) | packet_buf[pn_offset + i];
        }
        offset = pn_offset + pn_len;

        // 解密 payload
        var decrypted: [65536]u8 = undefined;
        const decrypted_len = protector.decrypt(
            pn,
            packet_buf[0..pn_offset],
            packet_buf[offset .. offset + payload_len - pn_len],
            &decrypted,
        ) catch return error.DecryptionFailed;

        // 处理帧
        return try self.processFrames(decrypted[0..decrypted_len]);
    }

    /// 处理 Handshake 包
    fn processHandshakePacket(self: *QuicClient, data: []const u8, start_offset: usize) !?ClientEvent {
        var offset = start_offset;

        // Length
        const length_result = types.decodeVarInt(data[offset..]);
        offset += length_result.len;
        const payload_len: usize = @intCast(length_result.value);

        if (offset + payload_len > data.len) return error.PacketTooShort;

        // 需要 Handshake 密钥
        const hs_keys = self.handshake_keys orelse {
            // 尝试派生 Handshake 密钥
            if (self.crypto_ctx) |*ctx| {
                if (ctx.shared_secret != null) {
                    const keys = try ctx.deriveHandshakeKeys();
                    self.handshake_keys = keys;
                    self.handshake_protector = PacketProtector.init(&keys.server);
                } else {
                    return error.NoHandshakeKeys;
                }
            } else {
                return error.NoHandshakeKeys;
            }
            return try self.processHandshakePacket(data, start_offset);
        };

        var protector = PacketProtector.init(&hs_keys.server);

        // 解除头部保护
        var packet_buf: [65536]u8 = undefined;
        @memcpy(packet_buf[0..data.len], data);

        const pn_offset = offset;
        protector.unprotectHeader(&packet_buf, pn_offset, data.len);

        // 获取包号
        const pn_len: usize = (packet_buf[0] & 0x03) + 1;
        var pn: u64 = 0;
        for (0..pn_len) |i| {
            pn = (pn << 8) | packet_buf[pn_offset + i];
        }
        offset = pn_offset + pn_len;

        // 解密
        var decrypted: [65536]u8 = undefined;
        const decrypted_len = protector.decrypt(
            pn,
            packet_buf[0..pn_offset],
            packet_buf[offset .. offset + payload_len - pn_len],
            &decrypted,
        ) catch return error.DecryptionFailed;

        return try self.processFrames(decrypted[0..decrypted_len]);
    }

    /// 处理 Short Header 包
    fn processShortHeaderPacket(self: *QuicClient, data: []const u8) !?ClientEvent {
        if (!self.connected) return error.NotConnected;

        const app_keys = self.app_keys orelse return error.NoAppKeys;
        var protector = PacketProtector.init(&app_keys.server);

        // 解除头部保护
        var packet_buf: [65536]u8 = undefined;
        @memcpy(packet_buf[0..data.len], data);

        const pn_offset = 1 + self.dst_conn_id.len;
        protector.unprotectHeader(&packet_buf, pn_offset, data.len);

        // 获取包号
        const pn_len: usize = (packet_buf[0] & 0x03) + 1;
        var pn: u64 = 0;
        for (0..pn_len) |i| {
            pn = (pn << 8) | packet_buf[pn_offset + i];
        }

        // 解密
        var decrypted: [65536]u8 = undefined;
        const decrypted_len = protector.decrypt(
            pn,
            packet_buf[0..pn_offset],
            packet_buf[pn_offset + pn_len .. data.len],
            &decrypted,
        ) catch return error.DecryptionFailed;

        return try self.processFrames(decrypted[0..decrypted_len]);
    }

    /// 处理帧
    fn processFrames(self: *QuicClient, data: []const u8) !?ClientEvent {
        var offset: usize = 0;

        while (offset < data.len) {
            const result = frame.FrameDecoder.decode(data[offset..]) catch break;
            offset += result.bytes_read;

            switch (result.frame) {
                .ack => |ack| {
                    // 处理 ACK
                    if (self.loss_detector) |*ld| {
                        ld.onAckReceived(ack.largest_ack);
                    }
                },
                .crypto => |crypto_frame| {
                    // 处理 CRYPTO 帧
                    const event = try self.processCryptoFrame(crypto_frame);
                    if (event) |e| return e;
                },
                .stream => |stream_data| {
                    // 处理 STREAM 帧
                    return ClientEvent{ .data_received = .{
                        .stream_id = stream_data.stream_id,
                        .data = stream_data.data,
                        .fin = stream_data.fin,
                    } };
                },
                .connection_close => |close_frame| {
                    self.connected = false;
                    return ClientEvent{ .connection_closed = .{
                        .error_code = close_frame.error_code,
                        .reason = close_frame.reason,
                    } };
                },
                .handshake_done => {
                    self.connected = true;
                    return ClientEvent.handshake_completed;
                },
                else => {},
            }
        }

        return null;
    }

    /// 处理 CRYPTO 帧
    fn processCryptoFrame(self: *QuicClient, crypto_frame: frame.CryptoFrame) !?ClientEvent {
        if (self.crypto_ctx == null) return null;

        const ctx = &self.crypto_ctx.?;

        switch (ctx.state) {
            .wait_server_hello => {
                try ctx.processServerHello(crypto_frame.data);

                // 派生 Handshake 密钥
                const hs_keys = try ctx.deriveHandshakeKeys();
                self.handshake_keys = hs_keys;
                self.handshake_protector = PacketProtector.init(&hs_keys.client);
            },
            .wait_encrypted_extensions => {
                try ctx.processEncryptedExtensions(crypto_frame.data);
            },
            .wait_certificate => {
                try ctx.processCertificate(crypto_frame.data);
            },
            .wait_certificate_verify => {
                try ctx.processCertificateVerify(crypto_frame.data);
            },
            .wait_finished => {
                try ctx.processFinished(crypto_frame.data);

                // 派生 Application 密钥
                const app_keys = try ctx.deriveApplicationKeys();
                self.app_keys = app_keys;
                self.app_protector = PacketProtector.init(&app_keys.client);

                // 发送客户端 Finished
                try self.sendFinished();

                self.connected = true;
                return ClientEvent.connected;
            },
            else => {},
        }

        return null;
    }

    /// 发送 Finished
    fn sendFinished(self: *QuicClient) !void {
        if (self.crypto_ctx == null) return;
        if (self.handshake_protector == null) return;

        var buf = &self.send_buffer;

        // 生成 Finished 消息
        var finished_data: [64]u8 = undefined;
        const finished_len = try self.crypto_ctx.?.generateFinished(&finished_data);

        // 构造 Handshake 包
        var payload_buf: [256]u8 = undefined;
        var payload_offset: usize = 0;

        // CRYPTO 帧
        const crypto_frame = frame.Frame{ .crypto = .{
            .offset = 0,
            .data = finished_data[0..finished_len],
        } };
        payload_offset += frame.FrameEncoder.encode(crypto_frame, payload_buf[payload_offset..]);

        // 构造 Long Header
        const pn = self.next_packet_number;
        self.next_packet_number += 1;

        var offset: usize = 0;

        // Handshake 包
        buf[offset] = 0xe0 | 0x03; // Form=1, Fixed=1, Type=Handshake, PN Len=4
        offset += 1;

        // Version
        buf[offset] = 0x00;
        buf[offset + 1] = 0x00;
        buf[offset + 2] = 0x00;
        buf[offset + 3] = 0x01;
        offset += 4;

        // Dest Conn ID
        buf[offset] = self.dst_conn_id.len;
        offset += 1;
        @memcpy(buf[offset .. offset + self.dst_conn_id.len], self.dst_conn_id.id[0..self.dst_conn_id.len]);
        offset += self.dst_conn_id.len;

        // Src Conn ID
        buf[offset] = self.src_conn_id.len;
        offset += 1;
        @memcpy(buf[offset .. offset + self.src_conn_id.len], self.src_conn_id.id[0..self.src_conn_id.len]);
        offset += self.src_conn_id.len;

        // Length
        const packet_number_len: usize = 4;
        const total_len = packet_number_len + payload_offset + 16;
        offset += types.encodeVarInt(buf[offset..], total_len);

        // Packet Number
        const pn_offset = offset;
        buf[offset] = @intCast((pn >> 24) & 0xff);
        buf[offset + 1] = @intCast((pn >> 16) & 0xff);
        buf[offset + 2] = @intCast((pn >> 8) & 0xff);
        buf[offset + 3] = @intCast(pn & 0xff);
        offset += 4;

        // Payload
        const payload_start = offset;
        @memcpy(buf[offset .. offset + payload_offset], payload_buf[0..payload_offset]);
        offset += payload_offset;

        // 加密
        if (self.handshake_protector) |*protector| {
            const encrypted_len = protector.encrypt(
                pn,
                buf[0..pn_offset],
                buf[payload_start .. payload_start + payload_offset],
                buf[payload_start..],
            ) catch payload_offset;
            offset = payload_start + encrypted_len;

            protector.protectHeader(buf, pn_offset, 4);
        }

        // 发送
        _ = try posix.sendto(self.socket.?, buf[0..offset], 0, &self.config.server_address.any, self.config.server_address.getOsSockLen());
    }

    /// 发送数据
    pub fn send(self: *QuicClient, stream_id: u64, data: []const u8, fin: bool) !void {
        if (!self.connected) return error.NotConnected;
        if (self.app_protector == null) return error.NoAppKeys;

        var buf = &self.send_buffer;

        // 构造 STREAM 帧
        var payload_buf: [65536]u8 = undefined;
        var payload_offset: usize = 0;

        const stream_frame = frame.Frame{
            .stream = .{
                .stream_id = stream_id,
                .offset = 0, // 简化：每次从 0 开始
                .data = data,
                .fin = fin,
            },
        };
        payload_offset += frame.FrameEncoder.encode(stream_frame, payload_buf[payload_offset..]);

        // 构造 Short Header 包
        const pn = self.next_packet_number;
        self.next_packet_number += 1;

        var offset: usize = 0;

        // First byte: Short Header, Spin=0, Reserved=0, Key Phase=0, PN Len=4
        buf[offset] = 0x40 | 0x03;
        offset += 1;

        // Dest Conn ID
        @memcpy(buf[offset .. offset + self.dst_conn_id.len], self.dst_conn_id.id[0..self.dst_conn_id.len]);
        offset += self.dst_conn_id.len;

        // Packet Number
        const pn_offset = offset;
        buf[offset] = @intCast((pn >> 24) & 0xff);
        buf[offset + 1] = @intCast((pn >> 16) & 0xff);
        buf[offset + 2] = @intCast((pn >> 8) & 0xff);
        buf[offset + 3] = @intCast(pn & 0xff);
        offset += 4;

        // Payload
        const payload_start = offset;
        @memcpy(buf[offset .. offset + payload_offset], payload_buf[0..payload_offset]);
        offset += payload_offset;

        // 加密
        if (self.app_protector) |*protector| {
            const encrypted_len = protector.encrypt(
                pn,
                buf[0..pn_offset],
                buf[payload_start .. payload_start + payload_offset],
                buf[payload_start..],
            ) catch payload_offset;
            offset = payload_start + encrypted_len;

            protector.protectHeader(buf, pn_offset, 4);
        }

        // 发送
        _ = try posix.sendto(self.socket.?, buf[0..offset], 0, &self.config.server_address.any, self.config.server_address.getOsSockLen());

        // 记录发送
        if (self.loss_detector) |*ld| {
            ld.onPacketSent(pn, offset, true);
        }
    }

    /// 接收数据
    pub fn recv(self: *QuicClient) !?ClientEvent {
        if (self.socket == null) return error.NotConnected;

        var src_addr: net.Address = undefined;
        var addr_len: posix.socklen_t = @sizeOf(@TypeOf(src_addr.any));

        const n = posix.recvfrom(
            self.socket.?,
            &self.recv_buffer,
            0,
            &src_addr.any,
            &addr_len,
        ) catch |err| switch (err) {
            error.WouldBlock => return null,
            else => return err,
        };

        if (n == 0) return null;

        return try self.processPacket(self.recv_buffer[0..n]);
    }

    /// 关闭连接
    pub fn close(self: *QuicClient, error_code: u64, reason: []const u8) !void {
        if (self.socket == null) return;

        var buf = &self.send_buffer;

        // 构造 CONNECTION_CLOSE 帧
        var payload_buf: [256]u8 = undefined;
        var payload_offset: usize = 0;

        const close_frame = frame.Frame{ .connection_close = .{
            .error_code = error_code,
            .frame_type = 0,
            .reason = reason,
        } };
        payload_offset += frame.FrameEncoder.encode(close_frame, payload_buf[payload_offset..]);

        // 发送 Short Header 包
        const pn = self.next_packet_number;
        self.next_packet_number += 1;

        var offset: usize = 0;

        buf[offset] = 0x40 | 0x03;
        offset += 1;

        @memcpy(buf[offset .. offset + self.dst_conn_id.len], self.dst_conn_id.id[0..self.dst_conn_id.len]);
        offset += self.dst_conn_id.len;

        const pn_offset = offset;
        buf[offset] = @intCast((pn >> 24) & 0xff);
        buf[offset + 1] = @intCast((pn >> 16) & 0xff);
        buf[offset + 2] = @intCast((pn >> 8) & 0xff);
        buf[offset + 3] = @intCast(pn & 0xff);
        offset += 4;

        const payload_start = offset;
        @memcpy(buf[offset .. offset + payload_offset], payload_buf[0..payload_offset]);
        offset += payload_offset;

        if (self.app_protector) |*protector| {
            const encrypted_len = protector.encrypt(
                pn,
                buf[0..pn_offset],
                buf[payload_start .. payload_start + payload_offset],
                buf[payload_start..],
            ) catch payload_offset;
            offset = payload_start + encrypted_len;

            protector.protectHeader(buf, pn_offset, 4);
        }

        _ = posix.sendto(self.socket.?, buf[0..offset], 0, &self.config.server_address.any, self.config.server_address.getOsSockLen()) catch {};

        self.connected = false;
    }

    /// 打开新流
    pub fn openStream(self: *QuicClient, bidirectional: bool) !u64 {
        if (!self.connected) return error.NotConnected;

        // 客户端发起的流 ID：
        // - 双向流：0, 4, 8, 12... (低 2 位 = 0b00)
        // - 单向流：2, 6, 10, 14... (低 2 位 = 0b10)
        const stream_id = if (self.conn) |*c| blk: {
            const base_id = c.next_stream_id;
            c.next_stream_id += 4;

            if (bidirectional) {
                break :blk base_id; // 0b00
            } else {
                break :blk base_id | 0x02; // 0b10
            }
        } else return error.NoConnection;

        return stream_id;
    }
};

// ============ 单元测试 ============

test "client init" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const addr = try net.Address.parseIp4("127.0.0.1", 4433);
    var client = QuicClient.init(allocator, .{
        .server_address = addr,
        .alpn = "h3",
    });
    defer client.deinit();

    try testing.expect(client.src_conn_id.len == 8);
    try testing.expect(client.dst_conn_id.len == 8);
    try testing.expect(!client.connected);
}
