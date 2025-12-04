//! QUIC 加密握手
//! 实现 TLS 1.3 握手集成

const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types.zig");
const tls = @import("tls.zig");
const Keys = tls.Keys;
const CipherSuite = tls.CipherSuite;
const Connection = @import("connection.zig").Connection;
const Role = @import("connection.zig").Role;

/// TLS 握手状态
pub const HandshakeState = enum {
    /// 初始状态
    start,
    /// 等待 ServerHello
    wait_server_hello,
    /// 等待 EncryptedExtensions
    wait_encrypted_extensions,
    /// 等待 Certificate
    wait_certificate,
    /// 等待 CertificateVerify
    wait_certificate_verify,
    /// 等待 Finished
    wait_finished,
    /// 等待客户端 Certificate
    wait_client_certificate,
    /// 等待客户端 CertificateVerify
    wait_client_certificate_verify,
    /// 等待客户端 Finished
    wait_client_finished,
    /// 握手完成
    connected,
};

/// TLS 扩展类型
pub const ExtensionType = enum(u16) {
    server_name = 0,
    supported_groups = 10,
    signature_algorithms = 13,
    alpn = 16,
    supported_versions = 43,
    key_share = 51,
    quic_transport_parameters = 0x0039,
    _,
};

/// TLS 消息类型
pub const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
    key_update = 24,
    _,
};

/// 支持的命名群组
pub const NamedGroup = enum(u16) {
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,
    x25519 = 0x001d,
    x448 = 0x001e,
    _,
};

/// 签名算法
pub const SignatureScheme = enum(u16) {
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,
    ed25519 = 0x0807,
    ed448 = 0x0808,
    _,
};

/// QUIC 加密上下文
pub const CryptoContext = struct {
    allocator: Allocator,
    role: Role,

    /// 握手状态
    state: HandshakeState = .start,

    /// 密码套件
    cipher_suite: CipherSuite = .aes_128_gcm,

    /// 握手转录哈希
    transcript_hash: std.crypto.hash.sha2.Sha256 = std.crypto.hash.sha2.Sha256.init(.{}),

    /// 密钥材料
    early_secret: ?[32]u8 = null,
    handshake_secret: ?[32]u8 = null,
    master_secret: ?[32]u8 = null,

    /// ECDH 私钥（X25519）
    private_key: ?[32]u8 = null,
    public_key: ?[32]u8 = null,

    /// 对端公钥
    peer_public_key: ?[32]u8 = null,

    /// 共享密钥
    shared_secret: ?[32]u8 = null,

    /// 客户端随机数
    client_random: [32]u8 = undefined,
    /// 服务端随机数
    server_random: [32]u8 = undefined,

    /// ALPN
    alpn: ?[]const u8 = null,

    /// 传输参数
    local_transport_params: ?types.TransportParameters = null,
    peer_transport_params: ?types.TransportParameters = null,

    pub fn init(allocator: Allocator, role: Role) CryptoContext {
        var ctx = CryptoContext{
            .allocator = allocator,
            .role = role,
        };

        // 生成 ECDH 密钥对
        var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
        const random = prng.random();

        var private_key: [32]u8 = undefined;
        random.bytes(&private_key);
        ctx.private_key = private_key;

        // 计算公钥（X25519）
        ctx.public_key = std.crypto.dh.X25519.recoverPublicKey(private_key) catch null;

        return ctx;
    }

    pub fn deinit(self: *CryptoContext) void {
        _ = self;
    }

    /// 生成 ClientHello 消息
    pub fn generateClientHello(self: *CryptoContext, buf: []u8) !usize {
        if (self.role != .client) return error.InvalidRole;
        if (self.state != .start) return error.InvalidState;

        var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
        const random = prng.random();

        var offset: usize = 0;

        // Handshake 消息头（后面填充）
        const header_offset = offset;
        offset += 4;

        // ProtocolVersion: TLS 1.2 (兼容)
        buf[offset] = 0x03;
        buf[offset + 1] = 0x03;
        offset += 2;

        // Random
        random.bytes(buf[offset .. offset + 32]);
        @memcpy(&self.client_random, buf[offset .. offset + 32]);
        offset += 32;

        // Session ID (空)
        buf[offset] = 0;
        offset += 1;

        // Cipher Suites
        const cipher_suites_offset = offset;
        offset += 2;
        // TLS_AES_128_GCM_SHA256
        buf[offset] = 0x13;
        buf[offset + 1] = 0x01;
        offset += 2;
        // TLS_AES_256_GCM_SHA384
        buf[offset] = 0x13;
        buf[offset + 1] = 0x02;
        offset += 2;
        // TLS_CHACHA20_POLY1305_SHA256
        buf[offset] = 0x13;
        buf[offset + 1] = 0x03;
        offset += 2;

        const cipher_suites_len = offset - cipher_suites_offset - 2;
        buf[cipher_suites_offset] = @intCast(cipher_suites_len >> 8);
        buf[cipher_suites_offset + 1] = @intCast(cipher_suites_len & 0xff);

        // Compression Methods (null)
        buf[offset] = 1;
        buf[offset + 1] = 0;
        offset += 2;

        // Extensions
        const extensions_offset = offset;
        offset += 2;

        // supported_versions 扩展
        offset = try self.writeExtSupportedVersions(buf, offset);

        // supported_groups 扩展
        offset = try self.writeExtSupportedGroups(buf, offset);

        // key_share 扩展
        offset = try self.writeExtKeyShare(buf, offset);

        // signature_algorithms 扩展
        offset = try self.writeExtSignatureAlgorithms(buf, offset);

        // ALPN 扩展（如果有）
        if (self.alpn) |alpn| {
            offset = try self.writeExtAlpn(buf, offset, alpn);
        }

        // QUIC 传输参数扩展
        if (self.local_transport_params) |params| {
            offset = try self.writeExtTransportParams(buf, offset, &params);
        }

        // 填充扩展长度
        const extensions_len = offset - extensions_offset - 2;
        buf[extensions_offset] = @intCast(extensions_len >> 8);
        buf[extensions_offset + 1] = @intCast(extensions_len & 0xff);

        // 填充 Handshake 消息头
        const msg_len = offset - header_offset - 4;
        buf[header_offset] = @intFromEnum(HandshakeType.client_hello);
        buf[header_offset + 1] = @intCast(msg_len >> 16);
        buf[header_offset + 2] = @intCast((msg_len >> 8) & 0xff);
        buf[header_offset + 3] = @intCast(msg_len & 0xff);

        // 更新转录哈希
        self.transcript_hash.update(buf[0..offset]);

        self.state = .wait_server_hello;
        return offset;
    }

    /// 处理 ServerHello 消息
    pub fn processServerHello(self: *CryptoContext, data: []const u8) !void {
        if (self.role != .client) return error.InvalidRole;
        if (self.state != .wait_server_hello) return error.InvalidState;

        // 更新转录哈希
        self.transcript_hash.update(data);

        var offset: usize = 0;

        // 验证消息类型
        if (data[offset] != @intFromEnum(HandshakeType.server_hello)) {
            return error.UnexpectedMessage;
        }
        offset += 1;

        // 消息长度
        const msg_len = (@as(u24, data[offset]) << 16) | (@as(u24, data[offset + 1]) << 8) | data[offset + 2];
        _ = msg_len;
        offset += 3;

        // 版本（应该是 0x0303）
        offset += 2;

        // Server Random
        @memcpy(&self.server_random, data[offset .. offset + 32]);
        offset += 32;

        // Session ID
        const session_id_len = data[offset];
        offset += 1 + session_id_len;

        // Cipher Suite
        const cipher_suite: u16 = (@as(u16, data[offset]) << 8) | data[offset + 1];
        self.cipher_suite = switch (cipher_suite) {
            0x1301 => .aes_128_gcm,
            0x1302 => .aes_256_gcm,
            0x1303 => .chacha20_poly1305,
            else => return error.UnsupportedCipherSuite,
        };
        offset += 2;

        // Compression Method (应该是 0)
        offset += 1;

        // 解析扩展
        if (offset < data.len) {
            const ext_len = (@as(u16, data[offset]) << 8) | data[offset + 1];
            offset += 2;

            const ext_end = offset + ext_len;
            while (offset < ext_end) {
                const ext_type: ExtensionType = @enumFromInt((@as(u16, data[offset]) << 8) | data[offset + 1]);
                offset += 2;
                const ext_data_len = (@as(u16, data[offset]) << 8) | data[offset + 1];
                offset += 2;

                switch (ext_type) {
                    .key_share => {
                        // 解析 key_share
                        const group: u16 = (@as(u16, data[offset]) << 8) | data[offset + 1];
                        if (group != @intFromEnum(NamedGroup.x25519)) {
                            return error.UnsupportedGroup;
                        }
                        const key_len = (@as(u16, data[offset + 2]) << 8) | data[offset + 3];
                        if (key_len != 32) return error.InvalidKeyLength;
                        @memcpy(&self.peer_public_key.?, data[offset + 4 .. offset + 4 + 32]);
                    },
                    else => {},
                }
                offset += ext_data_len;
            }
        }

        // 计算共享密钥
        if (self.private_key != null and self.peer_public_key != null) {
            self.shared_secret = std.crypto.dh.X25519.scalarmult(
                self.private_key.?,
                self.peer_public_key.?,
            ) catch return error.KeyExchangeFailed;
        }

        self.state = .wait_encrypted_extensions;
    }

    /// 派生 Handshake 密钥
    pub fn deriveHandshakeKeys(self: *CryptoContext) !struct { client: Keys, server: Keys } {
        const shared_secret = self.shared_secret orelse return error.NoSharedSecret;

        // Early Secret = HKDF-Extract(salt=0, IKM=0)
        const zero_key: [32]u8 = .{0} ** 32;
        var early_secret: [32]u8 = undefined;
        tls.hkdfExtract(&early_secret, &zero_key, &zero_key);
        self.early_secret = early_secret;

        // Derive-Secret(Early Secret, "derived", "")
        var derived: [32]u8 = undefined;
        const empty_hash = std.crypto.hash.sha2.Sha256.hash(&.{}, .{});
        tls.hkdfExpandLabel(&derived, &early_secret, "derived", &empty_hash);

        // Handshake Secret = HKDF-Extract(salt=derived, IKM=shared_secret)
        var handshake_secret: [32]u8 = undefined;
        tls.hkdfExtract(&handshake_secret, &derived, &shared_secret);
        self.handshake_secret = handshake_secret;

        // 获取转录哈希
        var transcript_hash: [32]u8 = undefined;
        var hash_copy = self.transcript_hash;
        hash_copy.final(&transcript_hash);

        // Client Handshake Traffic Secret
        var client_hs_secret: [32]u8 = undefined;
        tls.hkdfExpandLabel(&client_hs_secret, &handshake_secret, "c hs traffic", &transcript_hash);

        // Server Handshake Traffic Secret
        var server_hs_secret: [32]u8 = undefined;
        tls.hkdfExpandLabel(&server_hs_secret, &handshake_secret, "s hs traffic", &transcript_hash);

        // 派生密钥
        const client_keys = Keys.fromTrafficSecret(&client_hs_secret, self.cipher_suite);
        const server_keys = Keys.fromTrafficSecret(&server_hs_secret, self.cipher_suite);

        return .{ .client = client_keys, .server = server_keys };
    }

    /// 派生 Application 密钥
    pub fn deriveApplicationKeys(self: *CryptoContext) !struct { client: Keys, server: Keys } {
        const handshake_secret = self.handshake_secret orelse return error.NoHandshakeSecret;

        // Derive-Secret(Handshake Secret, "derived", "")
        var derived: [32]u8 = undefined;
        const empty_hash = std.crypto.hash.sha2.Sha256.hash(&.{}, .{});
        tls.hkdfExpandLabel(&derived, &handshake_secret, "derived", &empty_hash);

        // Master Secret = HKDF-Extract(salt=derived, IKM=0)
        const zero_key: [32]u8 = .{0} ** 32;
        var master_secret: [32]u8 = undefined;
        tls.hkdfExtract(&master_secret, &derived, &zero_key);
        self.master_secret = master_secret;

        // 获取转录哈希
        var transcript_hash: [32]u8 = undefined;
        var hash_copy = self.transcript_hash;
        hash_copy.final(&transcript_hash);

        // Client Application Traffic Secret 0
        var client_app_secret: [32]u8 = undefined;
        tls.hkdfExpandLabel(&client_app_secret, &master_secret, "c ap traffic", &transcript_hash);

        // Server Application Traffic Secret 0
        var server_app_secret: [32]u8 = undefined;
        tls.hkdfExpandLabel(&server_app_secret, &master_secret, "s ap traffic", &transcript_hash);

        // 派生密钥
        const client_keys = Keys.fromTrafficSecret(&client_app_secret, self.cipher_suite);
        const server_keys = Keys.fromTrafficSecret(&server_app_secret, self.cipher_suite);

        return .{ .client = client_keys, .server = server_keys };
    }

    /// 处理 EncryptedExtensions 消息
    pub fn processEncryptedExtensions(self: *CryptoContext, data: []const u8) !void {
        if (self.role != .client) return error.InvalidRole;
        if (self.state != .wait_encrypted_extensions) return error.InvalidState;

        // 更新转录哈希
        self.transcript_hash.update(data);

        var offset: usize = 0;

        // 验证消息类型
        if (data[offset] != @intFromEnum(HandshakeType.encrypted_extensions)) {
            return error.UnexpectedMessage;
        }
        offset += 1;

        // 消息长度
        const msg_len = (@as(u24, data[offset]) << 16) | (@as(u24, data[offset + 1]) << 8) | data[offset + 2];
        offset += 3;

        // 扩展列表长度
        const ext_len = (@as(u16, data[offset]) << 8) | data[offset + 1];
        offset += 2;

        const ext_end = offset + ext_len;
        while (offset < ext_end and offset + 4 <= data.len) {
            const ext_type: ExtensionType = @enumFromInt((@as(u16, data[offset]) << 8) | data[offset + 1]);
            offset += 2;
            const ext_data_len = (@as(u16, data[offset]) << 8) | data[offset + 1];
            offset += 2;

            switch (ext_type) {
                .alpn => {
                    // 解析 ALPN
                    if (ext_data_len >= 3) {
                        const alpn_len = data[offset + 2];
                        if (alpn_len > 0 and offset + 3 + alpn_len <= data.len) {
                            self.alpn = data[offset + 3 .. offset + 3 + alpn_len];
                        }
                    }
                },
                .quic_transport_parameters => {
                    // 解析 QUIC 传输参数
                    self.peer_transport_params = try parseTransportParams(data[offset .. offset + ext_data_len]);
                },
                else => {},
            }
            offset += ext_data_len;
        }

        _ = msg_len;
        self.state = .wait_certificate;
    }

    /// 处理 Certificate 消息
    pub fn processCertificate(self: *CryptoContext, data: []const u8) !void {
        if (self.state != .wait_certificate and self.state != .wait_client_certificate) {
            return error.InvalidState;
        }

        // 更新转录哈希
        self.transcript_hash.update(data);

        var offset: usize = 0;

        // 验证消息类型
        if (data[offset] != @intFromEnum(HandshakeType.certificate)) {
            return error.UnexpectedMessage;
        }
        offset += 1;

        // 消息长度
        const msg_len = (@as(u24, data[offset]) << 16) | (@as(u24, data[offset + 1]) << 8) | data[offset + 2];
        offset += 3;

        // Certificate Request Context（通常为空）
        const ctx_len = data[offset];
        offset += 1 + ctx_len;

        // Certificate List 长度
        const cert_list_len = (@as(u24, data[offset]) << 16) | (@as(u24, data[offset + 1]) << 8) | data[offset + 2];
        offset += 3;

        // 解析证书链（简化处理，仅记录第一个证书）
        if (cert_list_len > 0 and offset + 3 <= data.len) {
            const cert_len = (@as(u24, data[offset]) << 16) | (@as(u24, data[offset + 1]) << 8) | data[offset + 2];
            offset += 3;

            // 跳过证书数据（实际应用需要验证证书）
            offset += cert_len;

            // 跳过证书扩展
            if (offset + 2 <= data.len) {
                const cert_ext_len = (@as(u16, data[offset]) << 8) | data[offset + 1];
                offset += 2 + cert_ext_len;
            }
        }

        _ = msg_len;

        if (self.role == .client) {
            self.state = .wait_certificate_verify;
        } else {
            self.state = .wait_client_certificate_verify;
        }
    }

    /// 处理 CertificateVerify 消息
    pub fn processCertificateVerify(self: *CryptoContext, data: []const u8) !void {
        if (self.state != .wait_certificate_verify and self.state != .wait_client_certificate_verify) {
            return error.InvalidState;
        }

        // 更新转录哈希
        self.transcript_hash.update(data);

        var offset: usize = 0;

        // 验证消息类型
        if (data[offset] != @intFromEnum(HandshakeType.certificate_verify)) {
            return error.UnexpectedMessage;
        }
        offset += 1;

        // 消息长度
        const msg_len = (@as(u24, data[offset]) << 16) | (@as(u24, data[offset + 1]) << 8) | data[offset + 2];
        offset += 3;

        // 签名算法
        const sig_scheme: SignatureScheme = @enumFromInt((@as(u16, data[offset]) << 8) | data[offset + 1]);
        _ = sig_scheme;
        offset += 2;

        // 签名长度和签名数据
        const sig_len = (@as(u16, data[offset]) << 8) | data[offset + 1];
        offset += 2;

        // 跳过签名数据（实际应用需要验证签名）
        offset += sig_len;

        _ = msg_len;

        if (self.role == .client) {
            self.state = .wait_finished;
        } else {
            self.state = .wait_client_finished;
        }
    }

    /// 处理 Finished 消息
    pub fn processFinished(self: *CryptoContext, data: []const u8) !void {
        if (self.state != .wait_finished and self.state != .wait_client_finished) {
            return error.InvalidState;
        }

        var offset: usize = 0;

        // 验证消息类型
        if (data[offset] != @intFromEnum(HandshakeType.finished)) {
            return error.UnexpectedMessage;
        }
        offset += 1;

        // 消息长度
        const msg_len = (@as(u24, data[offset]) << 16) | (@as(u24, data[offset + 1]) << 8) | data[offset + 2];
        offset += 3;

        // Verify Data（32 字节 for SHA-256）
        if (msg_len != 32) return error.InvalidFinishedLength;

        // 计算预期的 verify_data
        const expected_verify_data = try self.computeFinishedVerifyData();

        // 验证
        const received_verify_data = data[offset .. offset + 32];
        if (!std.mem.eql(u8, &expected_verify_data, received_verify_data)) {
            return error.FinishedVerifyFailed;
        }

        // 更新转录哈希（在验证之后）
        self.transcript_hash.update(data);

        if (self.role == .client) {
            self.state = .connected;
        } else {
            self.state = .connected;
        }
    }

    /// 生成 Finished 消息
    pub fn generateFinished(self: *CryptoContext, buf: []u8) !usize {
        var offset: usize = 0;

        // 消息类型
        buf[offset] = @intFromEnum(HandshakeType.finished);
        offset += 1;

        // 消息长度（32 字节）
        buf[offset] = 0;
        buf[offset + 1] = 0;
        buf[offset + 2] = 32;
        offset += 3;

        // 计算 verify_data
        const verify_data = try self.computeFinishedVerifyData();
        @memcpy(buf[offset .. offset + 32], &verify_data);
        offset += 32;

        // 更新转录哈希
        self.transcript_hash.update(buf[0..offset]);

        return offset;
    }

    /// 计算 Finished 消息的 verify_data
    fn computeFinishedVerifyData(self: *CryptoContext) ![32]u8 {
        const handshake_secret = self.handshake_secret orelse return error.NoHandshakeSecret;

        // 根据角色选择正确的 traffic secret
        var traffic_secret: [32]u8 = undefined;
        var transcript_hash: [32]u8 = undefined;

        // 获取当前转录哈希
        var hash_copy = self.transcript_hash;
        hash_copy.final(&transcript_hash);

        // 计算 finished_key
        if (self.role == .client) {
            // 客户端发送 Finished 使用 client_handshake_traffic_secret
            tls.hkdfExpandLabel(&traffic_secret, &handshake_secret, "c hs traffic", &transcript_hash);
        } else {
            // 服务端发送 Finished 使用 server_handshake_traffic_secret
            tls.hkdfExpandLabel(&traffic_secret, &handshake_secret, "s hs traffic", &transcript_hash);
        }

        var finished_key: [32]u8 = undefined;
        const empty: [0]u8 = .{};
        tls.hkdfExpandLabel(&finished_key, &traffic_secret, "finished", &empty);

        // verify_data = HMAC(finished_key, transcript_hash)
        var verify_data: [32]u8 = undefined;
        var hmac = std.crypto.auth.hmac.HmacSha256.init(&finished_key);
        hmac.update(&transcript_hash);
        hmac.final(&verify_data);

        return verify_data;
    }

    /// 生成 ServerHello 消息（服务端）
    pub fn generateServerHello(self: *CryptoContext, buf: []u8) !usize {
        if (self.role != .server) return error.InvalidRole;
        if (self.state != .wait_server_hello) return error.InvalidState;

        var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
        const random = prng.random();

        var offset: usize = 0;

        // Handshake 消息头（后面填充）
        const header_offset = offset;
        offset += 4;

        // ProtocolVersion: TLS 1.2 (兼容)
        buf[offset] = 0x03;
        buf[offset + 1] = 0x03;
        offset += 2;

        // Random
        random.bytes(buf[offset .. offset + 32]);
        @memcpy(&self.server_random, buf[offset .. offset + 32]);
        offset += 32;

        // Session ID (回显客户端的，简化为空)
        buf[offset] = 0;
        offset += 1;

        // Cipher Suite
        const cs: u16 = switch (self.cipher_suite) {
            .aes_128_gcm => 0x1301,
            .aes_256_gcm => 0x1302,
            .chacha20_poly1305 => 0x1303,
        };
        buf[offset] = @intCast(cs >> 8);
        buf[offset + 1] = @intCast(cs & 0xff);
        offset += 2;

        // Compression Method (null)
        buf[offset] = 0;
        offset += 1;

        // Extensions
        const extensions_offset = offset;
        offset += 2;

        // supported_versions 扩展
        buf[offset] = @intCast(@intFromEnum(ExtensionType.supported_versions) >> 8);
        buf[offset + 1] = @intCast(@intFromEnum(ExtensionType.supported_versions) & 0xff);
        offset += 2;
        buf[offset] = 0;
        buf[offset + 1] = 2;
        offset += 2;
        buf[offset] = 0x03;
        buf[offset + 1] = 0x04;
        offset += 2;

        // key_share 扩展
        const public_key = self.public_key orelse return error.NoPublicKey;
        buf[offset] = @intCast(@intFromEnum(ExtensionType.key_share) >> 8);
        buf[offset + 1] = @intCast(@intFromEnum(ExtensionType.key_share) & 0xff);
        offset += 2;
        buf[offset] = 0;
        buf[offset + 1] = 36; // 2 + 2 + 32
        offset += 2;
        buf[offset] = @intCast(@intFromEnum(NamedGroup.x25519) >> 8);
        buf[offset + 1] = @intCast(@intFromEnum(NamedGroup.x25519) & 0xff);
        offset += 2;
        buf[offset] = 0;
        buf[offset + 1] = 32;
        offset += 2;
        @memcpy(buf[offset .. offset + 32], &public_key);
        offset += 32;

        // 填充扩展长度
        const extensions_len = offset - extensions_offset - 2;
        buf[extensions_offset] = @intCast(extensions_len >> 8);
        buf[extensions_offset + 1] = @intCast(extensions_len & 0xff);

        // 填充 Handshake 消息头
        const msg_len = offset - header_offset - 4;
        buf[header_offset] = @intFromEnum(HandshakeType.server_hello);
        buf[header_offset + 1] = @intCast(msg_len >> 16);
        buf[header_offset + 2] = @intCast((msg_len >> 8) & 0xff);
        buf[header_offset + 3] = @intCast(msg_len & 0xff);

        // 更新转录哈希
        self.transcript_hash.update(buf[0..offset]);

        // 计算共享密钥
        if (self.private_key != null and self.peer_public_key != null) {
            self.shared_secret = std.crypto.dh.X25519.scalarmult(
                self.private_key.?,
                self.peer_public_key.?,
            ) catch return error.KeyExchangeFailed;
        }

        self.state = .wait_encrypted_extensions;
        return offset;
    }

    /// 生成 EncryptedExtensions 消息（服务端）
    pub fn generateEncryptedExtensions(self: *CryptoContext, buf: []u8) !usize {
        if (self.role != .server) return error.InvalidRole;

        var offset: usize = 0;

        // 消息类型
        buf[offset] = @intFromEnum(HandshakeType.encrypted_extensions);
        offset += 1;

        // 消息长度占位
        const len_offset = offset;
        offset += 3;

        // 扩展列表长度占位
        const ext_len_offset = offset;
        offset += 2;

        // ALPN 扩展
        if (self.alpn) |alpn| {
            offset = try self.writeExtAlpn(buf, offset, alpn);
        }

        // QUIC 传输参数扩展
        if (self.local_transport_params) |params| {
            offset = try self.writeExtTransportParams(buf, offset, &params);
        }

        // 填充扩展列表长度
        const ext_len = offset - ext_len_offset - 2;
        buf[ext_len_offset] = @intCast(ext_len >> 8);
        buf[ext_len_offset + 1] = @intCast(ext_len & 0xff);

        // 填充消息长度
        const msg_len = offset - len_offset - 3;
        buf[len_offset] = @intCast(msg_len >> 16);
        buf[len_offset + 1] = @intCast((msg_len >> 8) & 0xff);
        buf[len_offset + 2] = @intCast(msg_len & 0xff);

        // 更新转录哈希
        self.transcript_hash.update(buf[0..offset]);

        return offset;
    }

    /// 处理 ClientHello 消息（服务端）
    pub fn processClientHello(self: *CryptoContext, data: []const u8) !void {
        if (self.role != .server) return error.InvalidRole;
        if (self.state != .start) return error.InvalidState;

        // 更新转录哈希
        self.transcript_hash.update(data);

        var offset: usize = 0;

        // 验证消息类型
        if (data[offset] != @intFromEnum(HandshakeType.client_hello)) {
            return error.UnexpectedMessage;
        }
        offset += 1;

        // 消息长度
        const msg_len = (@as(u24, data[offset]) << 16) | (@as(u24, data[offset + 1]) << 8) | data[offset + 2];
        _ = msg_len;
        offset += 3;

        // 版本
        offset += 2;

        // Client Random
        @memcpy(&self.client_random, data[offset .. offset + 32]);
        offset += 32;

        // Session ID
        const session_id_len = data[offset];
        offset += 1 + session_id_len;

        // Cipher Suites
        const cipher_suites_len = (@as(u16, data[offset]) << 8) | data[offset + 1];
        offset += 2;

        // 选择支持的密码套件
        var selected_suite: ?CipherSuite = null;
        var i: usize = 0;
        while (i < cipher_suites_len) : (i += 2) {
            const suite: u16 = (@as(u16, data[offset + i]) << 8) | data[offset + i + 1];
            if (suite == 0x1301) {
                selected_suite = .aes_128_gcm;
                break;
            } else if (suite == 0x1302) {
                selected_suite = .aes_256_gcm;
                break;
            } else if (suite == 0x1303) {
                selected_suite = .chacha20_poly1305;
                break;
            }
        }
        self.cipher_suite = selected_suite orelse return error.NoCipherSuiteMatch;
        offset += cipher_suites_len;

        // Compression Methods
        const comp_len = data[offset];
        offset += 1 + comp_len;

        // 扩展
        if (offset + 2 <= data.len) {
            const ext_len = (@as(u16, data[offset]) << 8) | data[offset + 1];
            offset += 2;

            const ext_end = offset + ext_len;
            while (offset < ext_end and offset + 4 <= data.len) {
                const ext_type: ExtensionType = @enumFromInt((@as(u16, data[offset]) << 8) | data[offset + 1]);
                offset += 2;
                const ext_data_len = (@as(u16, data[offset]) << 8) | data[offset + 1];
                offset += 2;

                switch (ext_type) {
                    .key_share => {
                        // 解析客户端 key_share
                        const list_len = (@as(u16, data[offset]) << 8) | data[offset + 1];
                        var key_offset = offset + 2;
                        const key_end = key_offset + list_len;
                        while (key_offset < key_end and key_offset + 4 <= data.len) {
                            const group: u16 = (@as(u16, data[key_offset]) << 8) | data[key_offset + 1];
                            const key_len = (@as(u16, data[key_offset + 2]) << 8) | data[key_offset + 3];
                            key_offset += 4;

                            if (group == @intFromEnum(NamedGroup.x25519) and key_len == 32) {
                                @memcpy(&self.peer_public_key.?, data[key_offset .. key_offset + 32]);
                                break;
                            }
                            key_offset += key_len;
                        }
                    },
                    .alpn => {
                        // 解析 ALPN
                        if (ext_data_len >= 3) {
                            const alpn_len = data[offset + 2];
                            if (alpn_len > 0 and offset + 3 + alpn_len <= data.len) {
                                self.alpn = data[offset + 3 .. offset + 3 + alpn_len];
                            }
                        }
                    },
                    .quic_transport_parameters => {
                        // 解析 QUIC 传输参数
                        self.peer_transport_params = try parseTransportParams(data[offset .. offset + ext_data_len]);
                    },
                    else => {},
                }
                offset += ext_data_len;
            }
        }

        self.state = .wait_server_hello;
    }

    // 扩展写入辅助函数

    fn writeExtSupportedVersions(self: *CryptoContext, buf: []u8, offset: usize) !usize {
        _ = self;
        var o = offset;

        // Extension Type
        buf[o] = @intCast(@intFromEnum(ExtensionType.supported_versions) >> 8);
        buf[o + 1] = @intCast(@intFromEnum(ExtensionType.supported_versions) & 0xff);
        o += 2;

        // Extension Data Length
        buf[o] = 0;
        buf[o + 1] = 3;
        o += 2;

        // Versions Length
        buf[o] = 2;
        o += 1;

        // TLS 1.3
        buf[o] = 0x03;
        buf[o + 1] = 0x04;
        o += 2;

        return o;
    }

    fn writeExtSupportedGroups(self: *CryptoContext, buf: []u8, offset: usize) !usize {
        _ = self;
        var o = offset;

        buf[o] = @intCast(@intFromEnum(ExtensionType.supported_groups) >> 8);
        buf[o + 1] = @intCast(@intFromEnum(ExtensionType.supported_groups) & 0xff);
        o += 2;

        buf[o] = 0;
        buf[o + 1] = 4; // data length
        o += 2;

        buf[o] = 0;
        buf[o + 1] = 2; // groups length
        o += 2;

        // x25519
        buf[o] = @intCast(@intFromEnum(NamedGroup.x25519) >> 8);
        buf[o + 1] = @intCast(@intFromEnum(NamedGroup.x25519) & 0xff);
        o += 2;

        return o;
    }

    fn writeExtKeyShare(self: *CryptoContext, buf: []u8, offset: usize) !usize {
        var o = offset;
        const public_key = self.public_key orelse return error.NoPublicKey;

        buf[o] = @intCast(@intFromEnum(ExtensionType.key_share) >> 8);
        buf[o + 1] = @intCast(@intFromEnum(ExtensionType.key_share) & 0xff);
        o += 2;

        buf[o] = 0;
        buf[o + 1] = 38; // data length = 2 + 36
        o += 2;

        buf[o] = 0;
        buf[o + 1] = 36; // key share entry length
        o += 2;

        // x25519
        buf[o] = @intCast(@intFromEnum(NamedGroup.x25519) >> 8);
        buf[o + 1] = @intCast(@intFromEnum(NamedGroup.x25519) & 0xff);
        o += 2;

        // key length
        buf[o] = 0;
        buf[o + 1] = 32;
        o += 2;

        // public key
        @memcpy(buf[o .. o + 32], &public_key);
        o += 32;

        return o;
    }

    fn writeExtSignatureAlgorithms(self: *CryptoContext, buf: []u8, offset: usize) !usize {
        _ = self;
        var o = offset;

        buf[o] = @intCast(@intFromEnum(ExtensionType.signature_algorithms) >> 8);
        buf[o + 1] = @intCast(@intFromEnum(ExtensionType.signature_algorithms) & 0xff);
        o += 2;

        buf[o] = 0;
        buf[o + 1] = 8; // data length
        o += 2;

        buf[o] = 0;
        buf[o + 1] = 6; // algorithms length
        o += 2;

        // ecdsa_secp256r1_sha256
        buf[o] = 0x04;
        buf[o + 1] = 0x03;
        o += 2;

        // rsa_pss_rsae_sha256
        buf[o] = 0x08;
        buf[o + 1] = 0x04;
        o += 2;

        // ed25519
        buf[o] = 0x08;
        buf[o + 1] = 0x07;
        o += 2;

        return o;
    }

    fn writeExtAlpn(self: *CryptoContext, buf: []u8, offset: usize, alpn: []const u8) !usize {
        _ = self;
        var o = offset;

        buf[o] = @intCast(@intFromEnum(ExtensionType.alpn) >> 8);
        buf[o + 1] = @intCast(@intFromEnum(ExtensionType.alpn) & 0xff);
        o += 2;

        const data_len = 2 + 1 + alpn.len;
        buf[o] = @intCast(data_len >> 8);
        buf[o + 1] = @intCast(data_len & 0xff);
        o += 2;

        const list_len = 1 + alpn.len;
        buf[o] = @intCast(list_len >> 8);
        buf[o + 1] = @intCast(list_len & 0xff);
        o += 2;

        buf[o] = @intCast(alpn.len);
        o += 1;

        @memcpy(buf[o .. o + alpn.len], alpn);
        o += alpn.len;

        return o;
    }

    fn writeExtTransportParams(self: *CryptoContext, buf: []u8, offset: usize, params: *const types.TransportParameters) !usize {
        _ = self;
        var o = offset;

        buf[o] = @intCast(@intFromEnum(ExtensionType.quic_transport_parameters) >> 8);
        buf[o + 1] = @intCast(@intFromEnum(ExtensionType.quic_transport_parameters) & 0xff);
        o += 2;

        // 传输参数内容（简化版）
        const params_offset = o;
        o += 2; // 先跳过长度字段

        // initial_max_data
        o = writeVarIntParam(buf, o, 0x04, params.initial_max_data);
        // initial_max_stream_data_bidi_local
        o = writeVarIntParam(buf, o, 0x05, params.initial_max_stream_data_bidi_local);
        // initial_max_stream_data_bidi_remote
        o = writeVarIntParam(buf, o, 0x06, params.initial_max_stream_data_bidi_remote);
        // initial_max_stream_data_uni
        o = writeVarIntParam(buf, o, 0x07, params.initial_max_stream_data_uni);
        // initial_max_streams_bidi
        o = writeVarIntParam(buf, o, 0x08, params.initial_max_streams_bidi);
        // initial_max_streams_uni
        o = writeVarIntParam(buf, o, 0x09, params.initial_max_streams_uni);

        // 填充长度
        const params_len = o - params_offset - 2;
        buf[params_offset] = @intCast(params_len >> 8);
        buf[params_offset + 1] = @intCast(params_len & 0xff);

        return o;
    }
};

fn writeVarIntParam(buf: []u8, offset: usize, param_id: u8, value: u64) usize {
    var o = offset;
    buf[o] = param_id;
    o += 1;

    const len = types.encodeVarInt(buf[o + 1 ..], value);
    buf[o] = @intCast(len);
    o += 1 + len;

    return o;
}

/// 解析传输参数
fn parseTransportParams(data: []const u8) !types.TransportParameters {
    var params = types.TransportParameters{};
    var offset: usize = 0;

    while (offset + 2 <= data.len) {
        // 参数 ID（变长整数）
        const id_result = types.decodeVarInt(data[offset..]);
        if (id_result.len == 0) break;
        const param_id = id_result.value;
        offset += id_result.len;

        if (offset >= data.len) break;

        // 参数长度（变长整数）
        const len_result = types.decodeVarInt(data[offset..]);
        if (len_result.len == 0) break;
        const param_len = len_result.value;
        offset += len_result.len;

        if (offset + param_len > data.len) break;

        // 参数值
        const param_data = data[offset .. offset + @as(usize, @intCast(param_len))];
        const value_result = types.decodeVarInt(param_data);

        switch (param_id) {
            0x04 => params.initial_max_data = value_result.value,
            0x05 => params.initial_max_stream_data_bidi_local = value_result.value,
            0x06 => params.initial_max_stream_data_bidi_remote = value_result.value,
            0x07 => params.initial_max_stream_data_uni = value_result.value,
            0x08 => params.initial_max_streams_bidi = value_result.value,
            0x09 => params.initial_max_streams_uni = value_result.value,
            0x0e => params.max_idle_timeout = value_result.value,
            0x03 => params.max_udp_payload_size = value_result.value,
            else => {}, // 忽略未知参数
        }

        offset += @intCast(param_len);
    }

    return params;
}

// ============ 单元测试 ============

test "crypto context init" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var ctx = CryptoContext.init(allocator, .client);
    defer ctx.deinit();

    try testing.expect(ctx.public_key != null);
    try testing.expect(ctx.private_key != null);
    try testing.expectEqual(HandshakeState.start, ctx.state);
}

test "generate client hello" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var ctx = CryptoContext.init(allocator, .client);
    defer ctx.deinit();

    ctx.local_transport_params = types.TransportParameters.defaultClient();

    var buf: [512]u8 = undefined;
    const len = try ctx.generateClientHello(&buf);

    try testing.expect(len > 0);
    try testing.expectEqual(HandshakeState.wait_server_hello, ctx.state);
    try testing.expectEqual(@as(u8, @intFromEnum(HandshakeType.client_hello)), buf[0]);
}
