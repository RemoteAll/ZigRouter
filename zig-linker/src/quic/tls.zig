//! QUIC-TLS 集成
//! RFC 9001: Using TLS to Secure QUIC
//!
//! QUIC 使用 TLS 1.3 进行密钥协商，但与标准 TLS over TCP 不同：
//! - TLS 记录不使用 TLS 记录层，而是直接在 CRYPTO 帧中传输
//! - 使用 QUIC 特定的密钥派生
//! - 包保护使用 AEAD + Header Protection

const std = @import("std");
const crypto = std.crypto;
const types = @import("types.zig");
const ConnectionId = types.ConnectionId;
const Version = types.Version;
const PacketNumberSpace = types.PacketNumberSpace;

/// AEAD 算法
pub const AeadAlgorithm = enum {
    aes_128_gcm,
    aes_256_gcm,
    chacha20_poly1305,
};

/// 密钥材料
pub const KeyMaterial = struct {
    /// 密钥
    key: [32]u8 = undefined,
    key_len: u8 = 0,
    /// IV
    iv: [12]u8 = undefined,
    /// Header Protection 密钥
    hp_key: [32]u8 = undefined,
    hp_key_len: u8 = 0,

    pub fn getKey(self: *const KeyMaterial) []const u8 {
        return self.key[0..self.key_len];
    }

    pub fn getHpKey(self: *const KeyMaterial) []const u8 {
        return self.hp_key[0..self.hp_key_len];
    }
};

/// 加密级别
pub const EncryptionLevel = enum {
    initial,
    handshake,
    application,
};

/// QUIC 密钥管理
pub const Keys = struct {
    /// 客户端密钥
    client: KeyMaterial = .{},
    /// 服务端密钥
    server: KeyMaterial = .{},
    /// AEAD 算法
    aead: AeadAlgorithm = .aes_128_gcm,

    /// Initial 密钥派生（RFC 9001 Section 5.2）
    ///
    /// Initial 密钥使用固定的盐值和目标连接 ID 派生
    pub fn deriveInitial(dest_cid: *const ConnectionId, version: Version) Keys {
        // QUIC v1 Initial 盐值
        const initial_salt_v1 = [_]u8{
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
            0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
            0xcc, 0xbb, 0x7f, 0x0a,
        };

        // QUIC v2 Initial 盐值
        const initial_salt_v2 = [_]u8{
            0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
            0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
            0xf9, 0xbd, 0x2e, 0xd9,
        };

        const salt = switch (version) {
            .v1 => &initial_salt_v1,
            .v2 => &initial_salt_v2,
            else => &initial_salt_v1,
        };

        // 从 DCID 派生 Initial Secret
        var initial_secret: [32]u8 = undefined;
        hkdfExtract(&initial_secret, salt, dest_cid.slice());

        var keys = Keys{ .aead = .aes_128_gcm };

        // 派生客户端密钥
        deriveSecrets(&keys.client, &initial_secret, "client in", 16);

        // 派生服务端密钥
        deriveSecrets(&keys.server, &initial_secret, "server in", 16);

        return keys;
    }
};

/// HKDF-Extract (RFC 5869)
fn hkdfExtract(out: *[32]u8, salt: []const u8, ikm: []const u8) void {
    const Hmac = crypto.auth.sha2.HmacSha256;
    var hmac = Hmac.init(salt);
    hmac.update(ikm);
    hmac.final(out);
}

/// HKDF-Expand-Label (RFC 8446 + QUIC 变体)
fn hkdfExpandLabel(out: []u8, secret: *const [32]u8, label: []const u8, context: []const u8) void {
    const Hmac = crypto.auth.sha2.HmacSha256;

    // 构建 HKDF-Expand 的 info
    // struct {
    //    uint16 length = Length;
    //    opaque label<7..255> = "tls13 " + Label;
    //    opaque context<0..255> = Context;
    // }
    var info: [256]u8 = undefined;
    var info_len: usize = 0;

    // length (2 bytes)
    info[0] = 0;
    info[1] = @intCast(out.len);
    info_len = 2;

    // label length + "tls13 " + label
    const full_label_len = 6 + label.len;
    info[info_len] = @intCast(full_label_len);
    info_len += 1;
    @memcpy(info[info_len .. info_len + 6], "tls13 ");
    info_len += 6;
    @memcpy(info[info_len .. info_len + label.len], label);
    info_len += label.len;

    // context length + context
    info[info_len] = @intCast(context.len);
    info_len += 1;
    if (context.len > 0) {
        @memcpy(info[info_len .. info_len + context.len], context);
        info_len += context.len;
    }

    // HKDF-Expand: T(1) = HMAC(PRK, info || 0x01)
    var hmac = Hmac.init(secret);
    hmac.update(info[0..info_len]);
    hmac.update(&[_]u8{0x01});

    var result: [32]u8 = undefined;
    hmac.final(&result);
    @memcpy(out, result[0..out.len]);
}

/// 从 secret 派生 key, iv, hp
fn deriveSecrets(material: *KeyMaterial, secret: *const [32]u8, label: []const u8, key_len: u8) void {
    // 派生 traffic secret
    var traffic_secret: [32]u8 = undefined;
    hkdfExpandLabel(&traffic_secret, secret, label, "");

    // 派生 key
    material.key_len = key_len;
    hkdfExpandLabel(material.key[0..key_len], &traffic_secret, "quic key", "");

    // 派生 iv
    hkdfExpandLabel(&material.iv, &traffic_secret, "quic iv", "");

    // 派生 hp key
    material.hp_key_len = key_len;
    hkdfExpandLabel(material.hp_key[0..key_len], &traffic_secret, "quic hp", "");
}

/// 包保护器
pub const PacketProtector = struct {
    keys: Keys,

    pub fn init(keys: Keys) PacketProtector {
        return .{ .keys = keys };
    }

    /// 加密载荷
    pub fn encryptPayload(
        self: *const PacketProtector,
        is_server: bool,
        packet_number: u64,
        header: []const u8,
        plaintext: []const u8,
        out: []u8,
    ) ![]const u8 {
        const material = if (is_server) &self.keys.server else &self.keys.client;

        // 构建 nonce = IV XOR packet_number
        var nonce: [12]u8 = material.iv;
        const pn_bytes = std.mem.toBytes(std.mem.nativeToBig(u64, packet_number));
        for (0..8) |i| {
            nonce[4 + i] ^= pn_bytes[i];
        }

        // AES-128-GCM 加密
        switch (self.keys.aead) {
            .aes_128_gcm => {
                const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
                const key = material.key[0..16].*;
                const tag_len = Aes128Gcm.tag_length;

                if (out.len < plaintext.len + tag_len) return error.BufferTooShort;

                var tag: [tag_len]u8 = undefined;
                Aes128Gcm.encrypt(out[0..plaintext.len], &tag, plaintext, header, nonce, key);
                @memcpy(out[plaintext.len .. plaintext.len + tag_len], &tag);

                return out[0 .. plaintext.len + tag_len];
            },
            .aes_256_gcm => {
                const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
                const key = material.key[0..32].*;
                const tag_len = Aes256Gcm.tag_length;

                if (out.len < plaintext.len + tag_len) return error.BufferTooShort;

                var tag: [tag_len]u8 = undefined;
                Aes256Gcm.encrypt(out[0..plaintext.len], &tag, plaintext, header, nonce, key);
                @memcpy(out[plaintext.len .. plaintext.len + tag_len], &tag);

                return out[0 .. plaintext.len + tag_len];
            },
            .chacha20_poly1305 => {
                const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
                const key = material.key[0..32].*;
                const tag_len = ChaCha20Poly1305.tag_length;

                if (out.len < plaintext.len + tag_len) return error.BufferTooShort;

                var tag: [tag_len]u8 = undefined;
                ChaCha20Poly1305.encrypt(out[0..plaintext.len], &tag, plaintext, header, nonce, key);
                @memcpy(out[plaintext.len .. plaintext.len + tag_len], &tag);

                return out[0 .. plaintext.len + tag_len];
            },
        }
    }

    /// 解密载荷
    pub fn decryptPayload(
        self: *const PacketProtector,
        is_server: bool,
        packet_number: u64,
        header: []const u8,
        ciphertext: []const u8,
        out: []u8,
    ) ![]const u8 {
        const material = if (is_server) &self.keys.client else &self.keys.server;

        // 构建 nonce
        var nonce: [12]u8 = material.iv;
        const pn_bytes = std.mem.toBytes(std.mem.nativeToBig(u64, packet_number));
        for (0..8) |i| {
            nonce[4 + i] ^= pn_bytes[i];
        }

        switch (self.keys.aead) {
            .aes_128_gcm => {
                const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
                const key = material.key[0..16].*;
                const tag_len = Aes128Gcm.tag_length;

                if (ciphertext.len < tag_len) return error.BufferTooShort;
                const payload_len = ciphertext.len - tag_len;
                if (out.len < payload_len) return error.BufferTooShort;

                const tag = ciphertext[payload_len..][0..tag_len].*;
                Aes128Gcm.decrypt(out[0..payload_len], ciphertext[0..payload_len], tag, header, nonce, key) catch {
                    return error.DecryptionFailed;
                };

                return out[0..payload_len];
            },
            .aes_256_gcm => {
                const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
                const key = material.key[0..32].*;
                const tag_len = Aes256Gcm.tag_length;

                if (ciphertext.len < tag_len) return error.BufferTooShort;
                const payload_len = ciphertext.len - tag_len;
                if (out.len < payload_len) return error.BufferTooShort;

                const tag = ciphertext[payload_len..][0..tag_len].*;
                Aes256Gcm.decrypt(out[0..payload_len], ciphertext[0..payload_len], tag, header, nonce, key) catch {
                    return error.DecryptionFailed;
                };

                return out[0..payload_len];
            },
            .chacha20_poly1305 => {
                const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
                const key = material.key[0..32].*;
                const tag_len = ChaCha20Poly1305.tag_length;

                if (ciphertext.len < tag_len) return error.BufferTooShort;
                const payload_len = ciphertext.len - tag_len;
                if (out.len < payload_len) return error.BufferTooShort;

                const tag = ciphertext[payload_len..][0..tag_len].*;
                ChaCha20Poly1305.decrypt(out[0..payload_len], ciphertext[0..payload_len], tag, header, nonce, key) catch {
                    return error.DecryptionFailed;
                };

                return out[0..payload_len];
            },
        }
    }

    /// 应用 Header Protection
    pub fn protectHeader(
        self: *const PacketProtector,
        is_server: bool,
        packet: []u8,
        pn_offset: usize,
        pn_length: usize,
    ) void {
        const material = if (is_server) &self.keys.server else &self.keys.client;

        // 采样点：pn_offset + 4
        const sample_offset = pn_offset + 4;
        if (sample_offset + 16 > packet.len) return;
        const sample = packet[sample_offset..][0..16];

        // 生成 mask
        var mask: [5]u8 = undefined;
        self.generateHpMask(material, sample, &mask);

        // 应用 mask 到第一字节
        if ((packet[0] & 0x80) == 0x80) {
            // Long header: mask 低 4 位
            packet[0] ^= mask[0] & 0x0f;
        } else {
            // Short header: mask 低 5 位
            packet[0] ^= mask[0] & 0x1f;
        }

        // 应用 mask 到包号
        for (0..pn_length) |i| {
            packet[pn_offset + i] ^= mask[1 + i];
        }
    }

    /// 移除 Header Protection
    pub fn unprotectHeader(
        self: *const PacketProtector,
        is_server: bool,
        packet: []u8,
        pn_offset: usize,
    ) !u2 {
        const material = if (is_server) &self.keys.client else &self.keys.server;

        // 采样点
        const sample_offset = pn_offset + 4;
        if (sample_offset + 16 > packet.len) return error.BufferTooShort;
        const sample = packet[sample_offset..][0..16];

        // 生成 mask
        var mask: [5]u8 = undefined;
        self.generateHpMask(material, sample, &mask);

        // 先解密第一字节以获取 pn_length
        if ((packet[0] & 0x80) == 0x80) {
            packet[0] ^= mask[0] & 0x0f;
        } else {
            packet[0] ^= mask[0] & 0x1f;
        }

        const pn_length: u2 = @truncate(packet[0] & 0x03);
        const pn_len: usize = @as(usize, pn_length) + 1;

        // 解密包号
        for (0..pn_len) |i| {
            packet[pn_offset + i] ^= mask[1 + i];
        }

        return pn_length;
    }

    fn generateHpMask(self: *const PacketProtector, material: *const KeyMaterial, sample: *const [16]u8, mask: *[5]u8) void {
        switch (self.keys.aead) {
            .aes_128_gcm => {
                // AES-ECB 加密 sample
                const Aes128 = crypto.core.aes.Aes128;
                const ctx = Aes128.initEnc(material.hp_key[0..16].*);
                var block: [16]u8 = undefined;
                ctx.encrypt(&block, sample);
                @memcpy(mask, block[0..5]);
            },
            .aes_256_gcm => {
                const Aes256 = crypto.core.aes.Aes256;
                const ctx = Aes256.initEnc(material.hp_key[0..32].*);
                var block: [16]u8 = undefined;
                ctx.encrypt(&block, sample);
                @memcpy(mask, block[0..5]);
            },
            .chacha20_poly1305 => {
                // ChaCha20 with counter = sample[0..4]
                const ChaCha20 = crypto.stream.chacha.ChaCha20IETF;
                const key = material.hp_key[0..32].*;
                const counter = std.mem.readInt(u32, sample[0..4], .little);
                const nonce = sample[4..16].*;

                var zeros: [5]u8 = .{ 0, 0, 0, 0, 0 };
                ChaCha20.xor(mask, &zeros, counter, nonce, key);
            },
        }
    }
};

// ============ 单元测试 ============

test "initial keys derivation" {
    const testing = std.testing;

    // RFC 9001 Appendix A 的测试向量
    const dcid = ConnectionId.init(&[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 });

    const keys = Keys.deriveInitial(&dcid, .v1);

    // 验证客户端 Initial 密钥
    // client_initial_secret = HKDF-Expand-Label(..., "client in", "", 32)
    // 这里只验证密钥长度，完整向量验证需要更多测试数据
    try testing.expectEqual(@as(u8, 16), keys.client.key_len);
    try testing.expectEqual(@as(u8, 16), keys.client.hp_key_len);

    try testing.expectEqual(@as(u8, 16), keys.server.key_len);
    try testing.expectEqual(@as(u8, 16), keys.server.hp_key_len);
}

test "packet protection roundtrip" {
    const testing = std.testing;

    const dcid = ConnectionId.init(&[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 });
    const keys = Keys.deriveInitial(&dcid, .v1);
    const protector = PacketProtector.init(keys);

    const header = "test header";
    const plaintext = "hello quic";
    var ciphertext: [256]u8 = undefined;
    var decrypted: [256]u8 = undefined;

    // 加密
    const encrypted = try protector.encryptPayload(false, 0, header, plaintext, &ciphertext);

    // 解密
    const result = try protector.decryptPayload(true, 0, header, encrypted, &decrypted);

    try testing.expectEqualStrings(plaintext, result);
}
