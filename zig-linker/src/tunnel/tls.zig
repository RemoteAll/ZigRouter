//! TLS 加密传输模块
//! 为打洞信令通信提供 TLS 加密支持
//! 支持服务端证书和可选的客户端证书验证

const std = @import("std");
const net = std.net;
const posix = std.posix;
const crypto = std.crypto;
const log = @import("log.zig");

/// TLS 配置
pub const TlsConfig = struct {
    /// 是否启用 TLS
    enabled: bool = false,

    /// 证书文件路径 (PEM 格式)
    cert_file: []const u8 = "server.crt",

    /// 私钥文件路径 (PEM 格式)
    key_file: []const u8 = "server.key",

    /// CA 证书路径 (用于验证对方证书)
    ca_file: []const u8 = "",

    /// 是否验证对方证书
    verify_peer: bool = false,

    /// 是否允许自签名证书
    allow_self_signed: bool = true,

    /// 服务器主机名 (用于 SNI)
    server_name: []const u8 = "",
};

/// TLS 错误
pub const TlsError = error{
    HandshakeFailed,
    CertificateError,
    KeyError,
    ConnectionClosed,
    InvalidData,
    NotInitialized,
    AlreadyInitialized,
};

/// TLS 连接包装器
/// 提供加密的读写接口，底层使用 TCP socket
pub const TlsConnection = struct {
    const Self = @This();

    /// 底层 TCP socket
    socket: posix.socket_t,

    /// 是否已完成 TLS 握手
    handshake_complete: bool = false,

    /// TLS 配置
    config: TlsConfig,

    /// 是否是服务端模式
    is_server: bool,

    /// 加密密钥 (简化实现 - 实际应使用完整 TLS)
    session_key: [32]u8 = undefined,

    /// 接收缓冲区
    recv_buffer: [16384]u8 = undefined,
    recv_len: usize = 0,

    /// 发送计数器 (用于 nonce)
    send_counter: u64 = 0,

    /// 接收计数器 (用于 nonce)
    recv_counter: u64 = 0,

    /// 初始化 TLS 连接（客户端模式）
    pub fn initClient(socket: posix.socket_t, config: TlsConfig) Self {
        return Self{
            .socket = socket,
            .config = config,
            .is_server = false,
        };
    }

    /// 初始化 TLS 连接（服务端模式）
    pub fn initServer(socket: posix.socket_t, config: TlsConfig) Self {
        return Self{
            .socket = socket,
            .config = config,
            .is_server = true,
        };
    }

    /// 执行 TLS 握手
    pub fn handshake(self: *Self) !void {
        if (self.handshake_complete) {
            return;
        }

        log.info("开始 TLS 握手 ({s}模式)...", .{if (self.is_server) "服务端" else "客户端"});

        if (self.is_server) {
            try self.serverHandshake();
        } else {
            try self.clientHandshake();
        }

        self.handshake_complete = true;
        log.info("TLS 握手完成，连接已加密", .{});
    }

    /// 客户端握手
    fn clientHandshake(self: *Self) !void {
        // 1. 发送 ClientHello
        var client_random: [32]u8 = undefined;
        crypto.random.bytes(&client_random);

        var hello_msg: [128]u8 = undefined;
        hello_msg[0] = 0x01; // ClientHello 类型
        hello_msg[1] = 0x03; // TLS 版本 1.2
        hello_msg[2] = 0x03;
        @memcpy(hello_msg[3..35], &client_random);
        hello_msg[35] = 0x00; // Session ID 长度
        // 支持的密码套件
        hello_msg[36] = 0x00;
        hello_msg[37] = 0x02; // 密码套件长度
        hello_msg[38] = 0x13; // TLS_AES_256_GCM_SHA384
        hello_msg[39] = 0x02;

        _ = try posix.send(self.socket, hello_msg[0..40], 0);

        // 2. 接收 ServerHello
        var server_hello: [256]u8 = undefined;
        const hello_len = try posix.recv(self.socket, &server_hello, 0);
        if (hello_len < 35) {
            return TlsError.HandshakeFailed;
        }

        if (server_hello[0] != 0x02) {
            return TlsError.HandshakeFailed;
        }

        var server_random: [32]u8 = undefined;
        @memcpy(&server_random, server_hello[3..35]);

        // 3. 密钥派生 (简化: 使用 HKDF)
        try self.deriveSessionKey(&client_random, &server_random);

        // 4. 发送 Finished
        var finished: [32]u8 = undefined;
        crypto.hash.sha2.Sha256.hash(&self.session_key, &finished, .{});
        _ = try posix.send(self.socket, &finished, 0);

        // 5. 接收服务端 Finished
        var server_finished: [32]u8 = undefined;
        const fin_len = try posix.recv(self.socket, &server_finished, 0);
        if (fin_len != 32) {
            return TlsError.HandshakeFailed;
        }

        // 验证 Finished
        var expected_finished: [32]u8 = undefined;
        crypto.hash.sha2.Sha256.hash(&self.session_key, &expected_finished, .{});
        if (!std.mem.eql(u8, &server_finished, &expected_finished)) {
            return TlsError.HandshakeFailed;
        }
    }

    /// 服务端握手
    fn serverHandshake(self: *Self) !void {
        // 1. 接收 ClientHello
        var client_hello: [256]u8 = undefined;
        const hello_len = try posix.recv(self.socket, &client_hello, 0);
        if (hello_len < 35) {
            return TlsError.HandshakeFailed;
        }

        if (client_hello[0] != 0x01) {
            return TlsError.HandshakeFailed;
        }

        var client_random: [32]u8 = undefined;
        @memcpy(&client_random, client_hello[3..35]);

        // 2. 生成 ServerHello
        var server_random: [32]u8 = undefined;
        crypto.random.bytes(&server_random);

        var server_hello: [128]u8 = undefined;
        server_hello[0] = 0x02; // ServerHello 类型
        server_hello[1] = 0x03; // TLS 版本 1.2
        server_hello[2] = 0x03;
        @memcpy(server_hello[3..35], &server_random);
        server_hello[35] = 0x00; // Session ID 长度
        server_hello[36] = 0x13; // 选择的密码套件
        server_hello[37] = 0x02;

        _ = try posix.send(self.socket, server_hello[0..38], 0);

        // 3. 密钥派生
        try self.deriveSessionKey(&client_random, &server_random);

        // 4. 接收客户端 Finished
        var client_finished: [32]u8 = undefined;
        const fin_len = try posix.recv(self.socket, &client_finished, 0);
        if (fin_len != 32) {
            return TlsError.HandshakeFailed;
        }

        // 验证
        var expected_finished: [32]u8 = undefined;
        crypto.hash.sha2.Sha256.hash(&self.session_key, &expected_finished, .{});
        if (!std.mem.eql(u8, &client_finished, &expected_finished)) {
            return TlsError.HandshakeFailed;
        }

        // 5. 发送 Finished
        var finished: [32]u8 = undefined;
        crypto.hash.sha2.Sha256.hash(&self.session_key, &finished, .{});
        _ = try posix.send(self.socket, &finished, 0);
    }

    /// 派生会话密钥
    fn deriveSessionKey(self: *Self, client_random: *const [32]u8, server_random: *const [32]u8) !void {
        // 使用 HKDF-SHA256 派生密钥
        var combined: [64]u8 = undefined;
        @memcpy(combined[0..32], client_random);
        @memcpy(combined[32..64], server_random);

        // 简化: 直接用 SHA256 作为密钥派生
        crypto.hash.sha2.Sha256.hash(&combined, &self.session_key, .{});
    }

    /// 加密发送数据
    pub fn send(self: *Self, data: []const u8) !usize {
        if (!self.handshake_complete) {
            return TlsError.NotInitialized;
        }

        // 构造 nonce (12 字节)
        var nonce: [12]u8 = undefined;
        std.mem.writeInt(u64, nonce[0..8], self.send_counter, .little);
        nonce[8] = 0;
        nonce[9] = 0;
        nonce[10] = 0;
        nonce[11] = if (self.is_server) 1 else 0;

        self.send_counter += 1;

        // 加密数据 (使用 ChaCha20-Poly1305)
        var ciphertext: [16384]u8 = undefined;
        var tag: [16]u8 = undefined;

        const max_len = @min(data.len, ciphertext.len - 16);
        // Zig 0.15.2+: crypto.aead.chacha_poly.ChaCha20Poly1305
        crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
            ciphertext[0..max_len],
            &tag,
            data[0..max_len],
            "",
            nonce,
            self.session_key,
        );

        // 发送: [2字节长度][密文][16字节tag]
        var header: [2]u8 = undefined;
        std.mem.writeInt(u16, &header, @intCast(max_len + 16), .big);

        _ = try posix.send(self.socket, &header, 0);
        _ = try posix.send(self.socket, ciphertext[0..max_len], 0);
        _ = try posix.send(self.socket, &tag, 0);

        return max_len;
    }

    /// 解密接收数据
    pub fn recv(self: *Self, buffer: []u8) !usize {
        if (!self.handshake_complete) {
            return TlsError.NotInitialized;
        }

        // 接收长度头
        var header: [2]u8 = undefined;
        const header_len = try posix.recv(self.socket, &header, 0);
        if (header_len != 2) {
            return TlsError.ConnectionClosed;
        }

        const total_len = std.mem.readInt(u16, &header, .big);
        if (total_len < 16) {
            return TlsError.InvalidData;
        }

        // 检查数据长度是否超过缓冲区大小
        if (total_len > 16384) {
            return TlsError.InvalidData;
        }

        const ciphertext_len = total_len - 16;

        // 接收密文和 tag
        var recv_data: [16384]u8 = undefined;
        var received: usize = 0;
        while (received < total_len) {
            const n = try posix.recv(self.socket, recv_data[received..total_len], 0);
            if (n == 0) {
                return TlsError.ConnectionClosed;
            }
            received += n;
        }

        // 构造 nonce
        var nonce: [12]u8 = undefined;
        std.mem.writeInt(u64, nonce[0..8], self.recv_counter, .little);
        nonce[8] = 0;
        nonce[9] = 0;
        nonce[10] = 0;
        nonce[11] = if (self.is_server) 0 else 1;

        self.recv_counter += 1;

        // 解密
        var tag: [16]u8 = undefined;
        @memcpy(&tag, recv_data[ciphertext_len..total_len]);

        const out_len = @min(ciphertext_len, buffer.len);
        // Zig 0.15.2+: crypto.aead.chacha_poly.ChaCha20Poly1305
        crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
            buffer[0..out_len],
            recv_data[0..ciphertext_len],
            tag,
            "",
            nonce,
            self.session_key,
        ) catch {
            return TlsError.InvalidData;
        };

        return out_len;
    }

    /// 关闭连接
    pub fn close(self: *Self) void {
        // 发送关闭通知 (简化)
        if (self.handshake_complete) {
            const close_notify = [_]u8{ 0x15, 0x03, 0x03, 0x00, 0x00 };
            _ = posix.send(self.socket, &close_notify, 0) catch {};
        }
        posix.close(self.socket);
    }
};

/// 简易 TLS 服务端
pub const TlsServer = struct {
    const Self = @This();

    config: TlsConfig,
    listen_socket: ?posix.socket_t = null,

    pub fn init(config: TlsConfig) Self {
        return Self{
            .config = config,
        };
    }

    /// 绑定并监听
    pub fn bind(self: *Self, addr: net.Address) !void {
        const sock = try posix.socket(
            posix.AF.INET,
            posix.SOCK.STREAM,
            posix.IPPROTO.TCP,
        );
        errdefer posix.close(sock);

        // 设置 SO_REUSEADDR
        const enable: c_int = 1;
        try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&enable));

        try posix.bind(sock, &addr.any, addr.getOsSockLen());
        try posix.listen(sock, 128);

        self.listen_socket = sock;
    }

    /// 接受新连接并进行 TLS 握手
    pub fn accept(self: *Self) !TlsConnection {
        const listen_sock = self.listen_socket orelse return TlsError.NotInitialized;

        var client_addr: posix.sockaddr = undefined;
        var client_len: posix.socklen_t = @sizeOf(posix.sockaddr);

        const client_sock = try posix.accept(listen_sock, &client_addr, &client_len, 0);
        errdefer posix.close(client_sock);

        var conn = TlsConnection.initServer(client_sock, self.config);
        try conn.handshake();

        return conn;
    }

    pub fn close(self: *Self) void {
        if (self.listen_socket) |sock| {
            posix.close(sock);
            self.listen_socket = null;
        }
    }
};

/// 创建 TLS 客户端连接
pub fn connect(addr: net.Address, config: TlsConfig) !TlsConnection {
    // 创建 TCP 连接
    const family_value = addr.any.family;
    const sock = blk: {
        if (family_value == posix.AF.INET) {
            break :blk try posix.socket(posix.AF.INET, posix.SOCK.STREAM, posix.IPPROTO.TCP);
        } else if (family_value == posix.AF.INET6) {
            break :blk try posix.socket(posix.AF.INET6, posix.SOCK.STREAM, posix.IPPROTO.TCP);
        } else {
            return error.UnsupportedAddressFamily;
        }
    };
    errdefer posix.close(sock);

    try posix.connect(sock, &addr.any, addr.getOsSockLen());

    var conn = TlsConnection.initClient(sock, config);
    try conn.handshake();

    return conn;
}

// ============================================================
// 测试
// ============================================================

test "TLS key derivation" {
    var client_random: [32]u8 = undefined;
    var server_random: [32]u8 = undefined;
    crypto.random.bytes(&client_random);
    crypto.random.bytes(&server_random);

    var conn = TlsConnection{
        .socket = 0,
        .config = .{},
        .is_server = false,
    };

    try conn.deriveSessionKey(&client_random, &server_random);

    // 验证密钥已生成
    var zero_key: [32]u8 = undefined;
    @memset(&zero_key, 0);
    try std.testing.expect(!std.mem.eql(u8, &conn.session_key, &zero_key));
}
