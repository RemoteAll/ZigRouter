//! QUIC 服务端实现
//! 提供简洁的服务端 API 用于接受 QUIC 连接

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

/// 服务端配置
pub const ServerConfig = struct {
    /// 监听地址
    bind_address: net.Address,
    /// ALPN 协议列表
    alpn: ?[]const u8 = null,
    /// 传输参数
    transport_params: ?types.TransportParameters = null,
    /// 最大连接数
    max_connections: u32 = 1000,
    /// 空闲超时（毫秒）
    idle_timeout_ms: u64 = 30000,
    /// 证书数据（DER 格式）
    certificate: ?[]const u8 = null,
    /// 私钥数据（DER 格式）
    private_key: ?[]const u8 = null,
};

/// 服务端事件
pub const ServerEvent = union(enum) {
    /// 新连接
    new_connection: *ServerConnection,
    /// 收到数据
    data_received: struct {
        connection: *ServerConnection,
        stream_id: u64,
        data: []const u8,
        fin: bool,
    },
    /// 连接关闭
    connection_closed: struct {
        connection: *ServerConnection,
        error_code: u64,
        reason: []const u8,
    },
    /// 握手完成
    handshake_completed: *ServerConnection,
};

/// 服务端连接
pub const ServerConnection = struct {
    allocator: Allocator,

    /// 连接 ID
    src_conn_id: types.ConnectionId,
    dst_conn_id: types.ConnectionId,

    /// 客户端地址
    client_addr: net.Address,

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

    /// 包号
    next_packet_number: u64 = 0,

    /// 是否已连接
    connected: bool = false,

    /// 握手状态
    handshake_completed: bool = false,

    /// 丢包恢复
    loss_detector: ?recovery.LossDetector = null,

    /// 用于标记是否应该从连接池中移除
    should_remove: bool = false,

    pub fn init(allocator: Allocator, client_addr: net.Address, dcid: types.ConnectionId, scid: types.ConnectionId) !*ServerConnection {
        const self = try allocator.create(ServerConnection);
        self.* = ServerConnection{
            .allocator = allocator,
            .src_conn_id = scid,
            .dst_conn_id = dcid,
            .client_addr = client_addr,
        };

        // 初始化加密上下文
        self.crypto_ctx = CryptoContext.init(allocator, .server);

        // 初始化连接
        self.conn = Connection.init(allocator, .server);
        self.conn.?.src_conn_id = scid;
        self.conn.?.dst_conn_id = dcid;

        // 初始化丢包检测
        self.loss_detector = recovery.LossDetector.init(allocator);

        // 派生 Initial 密钥（使用客户端的 DCID）
        const initial_keys = Keys.deriveInitial(&dcid);
        self.initial_keys = .{ .client = initial_keys.client, .server = initial_keys.server };
        self.initial_protector = PacketProtector.init(&initial_keys.server);

        return self;
    }

    pub fn deinit(self: *ServerConnection) void {
        if (self.conn) |*c| {
            c.deinit();
        }

        if (self.crypto_ctx) |*ctx| {
            ctx.deinit();
        }

        if (self.loss_detector) |*ld| {
            ld.deinit();
        }

        self.allocator.destroy(self);
    }

    /// 发送数据
    pub fn send(self: *ServerConnection, server: *QuicServer, stream_id: u64, data: []const u8, fin: bool) !void {
        if (!self.handshake_completed) return error.HandshakeNotComplete;
        if (self.app_protector == null) return error.NoAppKeys;

        var buf: [65536]u8 = undefined;

        // 构造 STREAM 帧
        var payload_buf: [65536]u8 = undefined;
        var payload_offset: usize = 0;

        const stream_frame = frame.Frame{ .stream = .{
            .stream_id = stream_id,
            .offset = 0,
            .data = data,
            .fin = fin,
        } };
        payload_offset += frame.FrameEncoder.encode(stream_frame, payload_buf[payload_offset..]);

        // 构造 Short Header 包
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

            protector.protectHeader(&buf, pn_offset, 4);
        }

        _ = try posix.sendto(server.socket.?, buf[0..offset], 0, &self.client_addr.any, self.client_addr.getOsSockLen());

        if (self.loss_detector) |*ld| {
            ld.onPacketSent(pn, offset, true);
        }
    }

    /// 关闭连接
    pub fn close(self: *ServerConnection, server: *QuicServer, error_code: u64, reason: []const u8) !void {
        var buf: [256]u8 = undefined;

        var payload_buf: [128]u8 = undefined;
        var payload_offset: usize = 0;

        const close_frame = frame.Frame{ .connection_close = .{
            .error_code = error_code,
            .frame_type = 0,
            .reason = reason,
        } };
        payload_offset += frame.FrameEncoder.encode(close_frame, payload_buf[payload_offset..]);

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

            protector.protectHeader(&buf, pn_offset, 4);
        }

        _ = posix.sendto(server.socket.?, buf[0..offset], 0, &self.client_addr.any, self.client_addr.getOsSockLen()) catch {};

        self.connected = false;
        self.should_remove = true;
    }
};

/// QUIC 服务端
pub const QuicServer = struct {
    allocator: Allocator,
    config: ServerConfig,

    /// UDP Socket
    socket: ?posix.socket_t = null,

    /// 活动连接（按 ConnectionId 索引）
    connections: std.AutoHashMap(u64, *ServerConnection),

    /// 发送/接收缓冲区
    send_buffer: [65536]u8 = undefined,
    recv_buffer: [65536]u8 = undefined,

    /// 是否正在运行
    running: bool = false,

    pub fn init(allocator: Allocator, config: ServerConfig) QuicServer {
        return QuicServer{
            .allocator = allocator,
            .config = config,
            .connections = std.AutoHashMap(u64, *ServerConnection).init(allocator),
        };
    }

    pub fn deinit(self: *QuicServer) void {
        // 关闭所有连接
        var it = self.connections.valueIterator();
        while (it.next()) |conn_ptr| {
            conn_ptr.*.deinit();
        }
        self.connections.deinit();

        if (self.socket) |sock| {
            posix.close(sock);
            self.socket = null;
        }
    }

    /// 开始监听
    pub fn listen(self: *QuicServer) !void {
        const addr_family: posix.sa_family_t = switch (self.config.bind_address.any.family) {
            posix.AF.INET => posix.AF.INET,
            posix.AF.INET6 => posix.AF.INET6,
            else => return error.UnsupportedAddressFamily,
        };

        self.socket = try posix.socket(addr_family, posix.SOCK.DGRAM, 0);
        errdefer {
            if (self.socket) |sock| posix.close(sock);
            self.socket = null;
        }

        // 绑定地址
        try posix.bind(self.socket.?, &self.config.bind_address.any, self.config.bind_address.getOsSockLen());

        // 设置非阻塞
        if (@import("builtin").os.tag != .windows) {
            const flags = try posix.fcntl(self.socket.?, posix.F.GETFL, 0);
            _ = try posix.fcntl(self.socket.?, posix.F.SETFL, @as(u32, @bitCast(flags)) | @as(u32, @intFromEnum(posix.O.NONBLOCK)));
        }

        self.running = true;
    }

    /// 接受连接/处理事件
    pub fn accept(self: *QuicServer) !?ServerEvent {
        if (self.socket == null) return error.NotListening;

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

        return try self.processPacket(self.recv_buffer[0..n], src_addr);
    }

    /// 处理收到的数据包
    fn processPacket(self: *QuicServer, data: []const u8, src_addr: net.Address) !?ServerEvent {
        if (data.len < 1) return null;

        const first_byte = data[0];
        const is_long = (first_byte & 0x80) != 0;

        if (is_long) {
            return try self.processLongHeaderPacket(data, src_addr);
        } else {
            return try self.processShortHeaderPacket(data, src_addr);
        }
    }

    /// 处理 Long Header 包
    fn processLongHeaderPacket(self: *QuicServer, data: []const u8, src_addr: net.Address) !?ServerEvent {
        if (data.len < 7) return error.PacketTooShort;

        const first_byte = data[0];
        const packet_type = (first_byte >> 4) & 0x03;

        var offset: usize = 1;

        // Version
        const version = (@as(u32, data[offset]) << 24) |
            (@as(u32, data[offset + 1]) << 16) |
            (@as(u32, data[offset + 2]) << 8) |
            data[offset + 3];
        offset += 4;

        if (version == 0) {
            // Version Negotiation（客户端不应发送）
            return null;
        }

        // Dest Conn ID
        const dcid_len = data[offset];
        offset += 1;
        if (offset + dcid_len > data.len) return error.PacketTooShort;

        var dcid: types.ConnectionId = .{};
        dcid.len = dcid_len;
        if (dcid_len > 0) {
            @memcpy(dcid.id[0..dcid_len], data[offset .. offset + dcid_len]);
        }
        offset += dcid_len;

        // Src Conn ID
        const scid_len = data[offset];
        offset += 1;
        if (offset + scid_len > data.len) return error.PacketTooShort;

        var scid: types.ConnectionId = .{};
        scid.len = scid_len;
        if (scid_len > 0) {
            @memcpy(scid.id[0..scid_len], data[offset .. offset + scid_len]);
        }
        offset += scid_len;

        // 查找或创建连接
        const conn_key = connectionIdToKey(&dcid);
        var conn = self.connections.get(conn_key);

        if (conn == null and packet_type == 0x00) {
            // Initial 包，创建新连接
            if (self.connections.count() >= self.config.max_connections) {
                return error.TooManyConnections;
            }

            // 生成服务端连接 ID
            var server_cid: types.ConnectionId = .{};
            server_cid.len = 8;
            var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
            prng.random().bytes(server_cid.id[0..8]);

            conn = try ServerConnection.init(self.allocator, src_addr, scid, server_cid);

            // 设置传输参数
            if (self.config.transport_params) |params| {
                conn.?.crypto_ctx.?.local_transport_params = params;
            } else {
                conn.?.crypto_ctx.?.local_transport_params = types.TransportParameters.defaultServer();
            }

            if (self.config.alpn) |alpn| {
                conn.?.crypto_ctx.?.alpn = alpn;
            }

            try self.connections.put(conn_key, conn.?);

            // 处理 Initial 包
            const event = try self.processInitialPacket(conn.?, data, offset);
            if (event) |e| return e;

            return ServerEvent{ .new_connection = conn.? };
        }

        if (conn) |c| {
            switch (packet_type) {
                0x00 => return try self.processInitialPacket(c, data, offset),
                0x02 => return try self.processHandshakePacket(c, data, offset),
                else => return null,
            }
        }

        return null;
    }

    /// 处理 Initial 包
    fn processInitialPacket(self: *QuicServer, conn: *ServerConnection, data: []const u8, start_offset: usize) !?ServerEvent {
        var offset = start_offset;

        // Token Length
        const token_len_result = types.decodeVarInt(data[offset..]);
        offset += token_len_result.len;
        offset += @intCast(token_len_result.value);

        // Length
        const length_result = types.decodeVarInt(data[offset..]);
        offset += length_result.len;
        const payload_len: usize = @intCast(length_result.value);

        if (offset + payload_len > data.len) return error.PacketTooShort;

        // 使用客户端的 Initial 密钥解密
        const client_keys = if (conn.initial_keys) |k| k.client else return error.NoKeys;
        var protector = PacketProtector.init(&client_keys);

        var packet_buf: [65536]u8 = undefined;
        @memcpy(packet_buf[0..data.len], data);

        const pn_offset = offset;
        protector.unprotectHeader(&packet_buf, pn_offset, data.len);

        const pn_len: usize = (packet_buf[0] & 0x03) + 1;
        var pn: u64 = 0;
        for (0..pn_len) |i| {
            pn = (pn << 8) | packet_buf[pn_offset + i];
        }
        offset = pn_offset + pn_len;

        var decrypted: [65536]u8 = undefined;
        const decrypted_len = protector.decrypt(
            pn,
            packet_buf[0..pn_offset],
            packet_buf[offset .. offset + payload_len - pn_len],
            &decrypted,
        ) catch return error.DecryptionFailed;

        // 处理帧
        return try self.processFrames(conn, decrypted[0..decrypted_len]);
    }

    /// 处理 Handshake 包
    fn processHandshakePacket(self: *QuicServer, conn: *ServerConnection, data: []const u8, start_offset: usize) !?ServerEvent {
        var offset = start_offset;

        // Length
        const length_result = types.decodeVarInt(data[offset..]);
        offset += length_result.len;
        const payload_len: usize = @intCast(length_result.value);

        if (offset + payload_len > data.len) return error.PacketTooShort;

        const hs_keys = conn.handshake_keys orelse return error.NoHandshakeKeys;
        var protector = PacketProtector.init(&hs_keys.client);

        var packet_buf: [65536]u8 = undefined;
        @memcpy(packet_buf[0..data.len], data);

        const pn_offset = offset;
        protector.unprotectHeader(&packet_buf, pn_offset, data.len);

        const pn_len: usize = (packet_buf[0] & 0x03) + 1;
        var pn: u64 = 0;
        for (0..pn_len) |i| {
            pn = (pn << 8) | packet_buf[pn_offset + i];
        }
        offset = pn_offset + pn_len;

        var decrypted: [65536]u8 = undefined;
        const decrypted_len = protector.decrypt(
            pn,
            packet_buf[0..pn_offset],
            packet_buf[offset .. offset + payload_len - pn_len],
            &decrypted,
        ) catch return error.DecryptionFailed;

        return try self.processFrames(conn, decrypted[0..decrypted_len]);
    }

    /// 处理 Short Header 包
    fn processShortHeaderPacket(self: *QuicServer, data: []const u8, src_addr: net.Address) !?ServerEvent {
        _ = src_addr;

        if (data.len < 2) return error.PacketTooShort;

        // 查找连接（通过遍历，实际应用可以用更高效的查找方式）
        var conn: ?*ServerConnection = null;
        var it = self.connections.valueIterator();
        while (it.next()) |c| {
            if (c.*.handshake_completed) {
                // 简化：假设匹配
                conn = c.*;
                break;
            }
        }

        if (conn == null) return null;
        const c = conn.?;

        const app_keys = c.app_keys orelse return error.NoAppKeys;
        var protector = PacketProtector.init(&app_keys.client);

        var packet_buf: [65536]u8 = undefined;
        @memcpy(packet_buf[0..data.len], data);

        const pn_offset = 1 + c.src_conn_id.len;
        protector.unprotectHeader(&packet_buf, pn_offset, data.len);

        const pn_len: usize = (packet_buf[0] & 0x03) + 1;
        var pn: u64 = 0;
        for (0..pn_len) |i| {
            pn = (pn << 8) | packet_buf[pn_offset + i];
        }

        var decrypted: [65536]u8 = undefined;
        const decrypted_len = protector.decrypt(
            pn,
            packet_buf[0..pn_offset],
            packet_buf[pn_offset + pn_len .. data.len],
            &decrypted,
        ) catch return error.DecryptionFailed;

        return try self.processFrames(c, decrypted[0..decrypted_len]);
    }

    /// 处理帧
    fn processFrames(self: *QuicServer, conn: *ServerConnection, data: []const u8) !?ServerEvent {
        var offset: usize = 0;

        while (offset < data.len) {
            const result = frame.FrameDecoder.decode(data[offset..]) catch break;
            offset += result.bytes_read;

            switch (result.frame) {
                .ack => |ack| {
                    if (conn.loss_detector) |*ld| {
                        ld.onAckReceived(ack.largest_ack);
                    }
                },
                .crypto => |crypto_frame| {
                    const event = try self.processCryptoFrame(conn, crypto_frame);
                    if (event) |e| return e;
                },
                .stream => |stream_data| {
                    return ServerEvent{ .data_received = .{
                        .connection = conn,
                        .stream_id = stream_data.stream_id,
                        .data = stream_data.data,
                        .fin = stream_data.fin,
                    } };
                },
                .connection_close => |close| {
                    conn.connected = false;
                    conn.should_remove = true;
                    return ServerEvent{ .connection_closed = .{
                        .connection = conn,
                        .error_code = close.error_code,
                        .reason = close.reason,
                    } };
                },
                else => {},
            }
        }

        return null;
    }

    /// 处理 CRYPTO 帧
    fn processCryptoFrame(self: *QuicServer, conn: *ServerConnection, crypto_frame: frame.CryptoFrame) !?ServerEvent {
        if (conn.crypto_ctx == null) return null;

        const ctx = &conn.crypto_ctx.?;

        switch (ctx.state) {
            .start => {
                // 处理 ClientHello
                try ctx.processClientHello(crypto_frame.data);

                // 发送 ServerHello
                try self.sendServerHello(conn);

                // 派生 Handshake 密钥
                const hs_keys = try ctx.deriveHandshakeKeys();
                conn.handshake_keys = hs_keys;
                conn.handshake_protector = PacketProtector.init(&hs_keys.server);

                // 发送 EncryptedExtensions, Certificate, CertificateVerify, Finished
                try self.sendHandshakeMessages(conn);
            },
            .wait_client_finished => {
                // 处理客户端 Finished
                try ctx.processFinished(crypto_frame.data);

                // 派生 Application 密钥
                const app_keys = try ctx.deriveApplicationKeys();
                conn.app_keys = app_keys;
                conn.app_protector = PacketProtector.init(&app_keys.server);

                conn.handshake_completed = true;
                conn.connected = true;

                // 发送 HANDSHAKE_DONE
                try self.sendHandshakeDone(conn);

                return ServerEvent{ .handshake_completed = conn };
            },
            else => {},
        }

        return null;
    }

    /// 发送 ServerHello
    fn sendServerHello(self: *QuicServer, conn: *ServerConnection) !void {
        if (conn.crypto_ctx == null) return;

        var buf = &self.send_buffer;

        // 生成 ServerHello
        var server_hello: [256]u8 = undefined;
        const sh_len = try conn.crypto_ctx.?.generateServerHello(&server_hello);

        // 构造 Initial 包
        var payload_buf: [1200]u8 = undefined;
        var payload_offset: usize = 0;

        // CRYPTO 帧
        const crypto_frame = frame.Frame{ .crypto = .{
            .offset = 0,
            .data = server_hello[0..sh_len],
        } };
        payload_offset += frame.FrameEncoder.encode(crypto_frame, payload_buf[payload_offset..]);

        // ACK 帧（确认客户端的 Initial）
        const ack_frame = frame.Frame{ .ack = .{
            .largest_ack = 0,
            .ack_delay = 0,
            .first_ack_range = 0,
            .ack_ranges = &.{},
        } };
        payload_offset += frame.FrameEncoder.encode(ack_frame, payload_buf[payload_offset..]);

        // Padding
        const min_size = 1200;
        const header_size = 50;
        const crypto_overhead = 16;
        while (payload_offset + header_size + crypto_overhead < min_size) {
            payload_buf[payload_offset] = 0x00;
            payload_offset += 1;
        }

        const pn = conn.next_packet_number;
        conn.next_packet_number += 1;

        var offset: usize = 0;

        buf[offset] = 0xc0 | 0x00 | 0x03;
        offset += 1;

        buf[offset] = 0x00;
        buf[offset + 1] = 0x00;
        buf[offset + 2] = 0x00;
        buf[offset + 3] = 0x01;
        offset += 4;

        buf[offset] = conn.dst_conn_id.len;
        offset += 1;
        @memcpy(buf[offset .. offset + conn.dst_conn_id.len], conn.dst_conn_id.id[0..conn.dst_conn_id.len]);
        offset += conn.dst_conn_id.len;

        buf[offset] = conn.src_conn_id.len;
        offset += 1;
        @memcpy(buf[offset .. offset + conn.src_conn_id.len], conn.src_conn_id.id[0..conn.src_conn_id.len]);
        offset += conn.src_conn_id.len;

        buf[offset] = 0;
        offset += 1;

        const total_len = 4 + payload_offset + 16;
        offset += types.encodeVarInt(buf[offset..], total_len);

        const pn_offset = offset;
        buf[offset] = @intCast((pn >> 24) & 0xff);
        buf[offset + 1] = @intCast((pn >> 16) & 0xff);
        buf[offset + 2] = @intCast((pn >> 8) & 0xff);
        buf[offset + 3] = @intCast(pn & 0xff);
        offset += 4;

        const payload_start = offset;
        @memcpy(buf[offset .. offset + payload_offset], payload_buf[0..payload_offset]);
        offset += payload_offset;

        if (conn.initial_protector) |*protector| {
            const encrypted_len = protector.encrypt(
                pn,
                buf[0..pn_offset],
                buf[payload_start .. payload_start + payload_offset],
                buf[payload_start..],
            ) catch payload_offset;
            offset = payload_start + encrypted_len;

            protector.protectHeader(buf, pn_offset, 4);
        }

        _ = try posix.sendto(self.socket.?, buf[0..offset], 0, &conn.client_addr.any, conn.client_addr.getOsSockLen());
    }

    /// 发送 Handshake 消息
    fn sendHandshakeMessages(self: *QuicServer, conn: *ServerConnection) !void {
        if (conn.crypto_ctx == null) return;
        if (conn.handshake_protector == null) return;

        var buf = &self.send_buffer;

        // 构造 EncryptedExtensions
        var ee_data: [256]u8 = undefined;
        const ee_len = try conn.crypto_ctx.?.generateEncryptedExtensions(&ee_data);

        // 简化：跳过 Certificate 和 CertificateVerify（PSK 模式）
        // 生成 Finished
        var finished_data: [64]u8 = undefined;
        const finished_len = try conn.crypto_ctx.?.generateFinished(&finished_data);

        // 构造 Handshake 包
        var payload_buf: [512]u8 = undefined;
        var payload_offset: usize = 0;

        // CRYPTO 帧（EncryptedExtensions）
        const ee_frame = frame.Frame{ .crypto = .{
            .offset = 0,
            .data = ee_data[0..ee_len],
        } };
        payload_offset += frame.FrameEncoder.encode(ee_frame, payload_buf[payload_offset..]);

        // CRYPTO 帧（Finished）
        const finished_frame = frame.Frame{ .crypto = .{
            .offset = ee_len,
            .data = finished_data[0..finished_len],
        } };
        payload_offset += frame.FrameEncoder.encode(finished_frame, payload_buf[payload_offset..]);

        const pn = conn.next_packet_number;
        conn.next_packet_number += 1;

        var offset: usize = 0;

        buf[offset] = 0xe0 | 0x03;
        offset += 1;

        buf[offset] = 0x00;
        buf[offset + 1] = 0x00;
        buf[offset + 2] = 0x00;
        buf[offset + 3] = 0x01;
        offset += 4;

        buf[offset] = conn.dst_conn_id.len;
        offset += 1;
        @memcpy(buf[offset .. offset + conn.dst_conn_id.len], conn.dst_conn_id.id[0..conn.dst_conn_id.len]);
        offset += conn.dst_conn_id.len;

        buf[offset] = conn.src_conn_id.len;
        offset += 1;
        @memcpy(buf[offset .. offset + conn.src_conn_id.len], conn.src_conn_id.id[0..conn.src_conn_id.len]);
        offset += conn.src_conn_id.len;

        const total_len = 4 + payload_offset + 16;
        offset += types.encodeVarInt(buf[offset..], total_len);

        const pn_offset = offset;
        buf[offset] = @intCast((pn >> 24) & 0xff);
        buf[offset + 1] = @intCast((pn >> 16) & 0xff);
        buf[offset + 2] = @intCast((pn >> 8) & 0xff);
        buf[offset + 3] = @intCast(pn & 0xff);
        offset += 4;

        const payload_start = offset;
        @memcpy(buf[offset .. offset + payload_offset], payload_buf[0..payload_offset]);
        offset += payload_offset;

        if (conn.handshake_protector) |*protector| {
            const encrypted_len = protector.encrypt(
                pn,
                buf[0..pn_offset],
                buf[payload_start .. payload_start + payload_offset],
                buf[payload_start..],
            ) catch payload_offset;
            offset = payload_start + encrypted_len;

            protector.protectHeader(buf, pn_offset, 4);
        }

        _ = try posix.sendto(self.socket.?, buf[0..offset], 0, &conn.client_addr.any, conn.client_addr.getOsSockLen());

        // 更新状态
        conn.crypto_ctx.?.state = .wait_client_finished;
    }

    /// 发送 HANDSHAKE_DONE
    fn sendHandshakeDone(self: *QuicServer, conn: *ServerConnection) !void {
        if (conn.app_protector == null) return;

        var buf = &self.send_buffer;

        var payload_buf: [16]u8 = undefined;
        payload_buf[0] = 0x1e; // HANDSHAKE_DONE
        const payload_offset: usize = 1;

        const pn = conn.next_packet_number;
        conn.next_packet_number += 1;

        var offset: usize = 0;

        buf[offset] = 0x40 | 0x03;
        offset += 1;

        @memcpy(buf[offset .. offset + conn.dst_conn_id.len], conn.dst_conn_id.id[0..conn.dst_conn_id.len]);
        offset += conn.dst_conn_id.len;

        const pn_offset = offset;
        buf[offset] = @intCast((pn >> 24) & 0xff);
        buf[offset + 1] = @intCast((pn >> 16) & 0xff);
        buf[offset + 2] = @intCast((pn >> 8) & 0xff);
        buf[offset + 3] = @intCast(pn & 0xff);
        offset += 4;

        const payload_start = offset;
        @memcpy(buf[offset .. offset + payload_offset], payload_buf[0..payload_offset]);
        offset += payload_offset;

        if (conn.app_protector) |*protector| {
            const encrypted_len = protector.encrypt(
                pn,
                buf[0..pn_offset],
                buf[payload_start .. payload_start + payload_offset],
                buf[payload_start..],
            ) catch payload_offset;
            offset = payload_start + encrypted_len;

            protector.protectHeader(buf, pn_offset, 4);
        }

        _ = try posix.sendto(self.socket.?, buf[0..offset], 0, &conn.client_addr.any, conn.client_addr.getOsSockLen());
    }

    /// 停止服务
    pub fn stop(self: *QuicServer) void {
        self.running = false;

        if (self.socket) |sock| {
            posix.close(sock);
            self.socket = null;
        }
    }

    /// 清理已关闭的连接
    pub fn cleanupClosedConnections(self: *QuicServer) void {
        var to_remove = std.ArrayList(u64).init(self.allocator);
        defer to_remove.deinit(self.allocator);

        var it = self.connections.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.should_remove) {
                to_remove.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            if (self.connections.fetchRemove(key)) |kv| {
                kv.value.deinit();
            }
        }
    }
};

/// 将 ConnectionId 转换为 HashMap 键
fn connectionIdToKey(cid: *const types.ConnectionId) u64 {
    if (cid.len == 0) return 0;

    var key: u64 = 0;
    const bytes_to_use = @min(8, cid.len);
    for (0..bytes_to_use) |i| {
        key = (key << 8) | cid.id[i];
    }
    return key;
}

// ============ 单元测试 ============

test "server init" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const addr = try net.Address.parseIp4("0.0.0.0", 4433);
    var server = QuicServer.init(allocator, .{
        .bind_address = addr,
        .alpn = "h3",
    });
    defer server.deinit();

    try testing.expect(!server.running);
    try testing.expect(server.socket == null);
}
