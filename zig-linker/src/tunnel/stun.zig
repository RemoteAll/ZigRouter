//! STUN 协议实现
//! 用于 NAT 类型检测和获取公网地址
//! 参考 RFC 3489 和 RFC 5389

const std = @import("std");
const net = std.net;
const posix = std.posix;
const types = @import("types.zig");
const log = @import("log.zig");
const net_utils = @import("net_utils.zig");

/// STUN 消息头部大小
const STUN_HEADER_SIZE = 20;

/// STUN Magic Cookie (RFC 5389)
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN 客户端错误
pub const StunError = error{
    NetworkError,
    Timeout,
    InvalidResponse,
    UnsupportedServer,
    OutOfMemory,
};

/// STUN 客户端配置
pub const StunConfig = struct {
    /// 接收超时 (毫秒)
    recv_timeout_ms: u32 = 3000,
    /// 重试次数
    retry_count: u32 = 3,
    /// 是否使用 RFC 5389 格式
    use_rfc5389: bool = true,
};

/// STUN 测试结果
pub const StunResult = struct {
    /// NAT 类型
    nat_type: types.NatType = .unknown,
    /// 本地端点
    local_endpoint: ?net.Address = null,
    /// 公网端点 (映射地址)
    public_endpoint: ?net.Address = null,
    /// 改变地址 (另一个服务器地址)
    changed_address: ?net.Address = null,
};

/// STUN 消息
pub const StunMessage = struct {
    /// 消息类型
    message_type: types.StunMessageType,
    /// 消息长度
    message_length: u16 = 0,
    /// Magic Cookie (RFC 5389) 或保留字段
    magic_cookie: u32 = 0,
    /// 事务 ID (12 字节)
    transaction_id: [12]u8 = undefined,
    /// 属性数据
    attributes: []const u8 = &.{},

    /// 序列化消息到缓冲区
    pub fn serialize(self: *const StunMessage, buf: []u8) !usize {
        if (buf.len < STUN_HEADER_SIZE) {
            return error.BufferTooSmall;
        }

        // 消息类型 (2 字节)
        std.mem.writeInt(u16, buf[0..2], @intFromEnum(self.message_type), .big);
        // 消息长度 (2 字节)
        std.mem.writeInt(u16, buf[2..4], self.message_length, .big);
        // Magic Cookie (4 字节)
        std.mem.writeInt(u32, buf[4..8], self.magic_cookie, .big);
        // Transaction ID (12 字节)
        @memcpy(buf[8..20], &self.transaction_id);

        // 属性数据
        if (self.attributes.len > 0) {
            if (buf.len < STUN_HEADER_SIZE + self.attributes.len) {
                return error.BufferTooSmall;
            }
            @memcpy(buf[STUN_HEADER_SIZE .. STUN_HEADER_SIZE + self.attributes.len], self.attributes);
        }

        return STUN_HEADER_SIZE + self.message_length;
    }

    /// 从缓冲区解析消息
    pub fn parse(buf: []const u8) !StunMessage {
        if (buf.len < STUN_HEADER_SIZE) {
            return error.InvalidMessage;
        }

        var msg = StunMessage{
            .message_type = @enumFromInt(std.mem.readInt(u16, buf[0..2], .big)),
            .message_length = std.mem.readInt(u16, buf[2..4], .big),
            .magic_cookie = std.mem.readInt(u32, buf[4..8], .big),
        };
        @memcpy(&msg.transaction_id, buf[8..20]);

        if (buf.len >= STUN_HEADER_SIZE + msg.message_length) {
            msg.attributes = buf[STUN_HEADER_SIZE .. STUN_HEADER_SIZE + msg.message_length];
        }

        return msg;
    }

    /// 验证响应是否匹配请求
    pub fn isSameTransaction(self: *const StunMessage, other: *const StunMessage) bool {
        return std.mem.eql(u8, &self.transaction_id, &other.transaction_id);
    }

    /// 生成随机事务 ID
    pub fn generateTransactionId(self: *StunMessage) void {
        var prng = std.Random.DefaultPrng.init(blk: {
            var seed: u64 = undefined;
            std.posix.getrandom(std.mem.asBytes(&seed)) catch {
                seed = @intCast(std.time.milliTimestamp());
            };
            break :blk seed;
        });
        prng.fill(&self.transaction_id);
    }
};

/// STUN 属性解析器
pub const StunAttribute = struct {
    attr_type: types.StunAttributeType,
    length: u16,
    value: []const u8,

    /// 解析映射地址属性
    pub fn parseMappedAddress(self: *const StunAttribute) ?net.Address {
        if (self.value.len < 8) return null;

        // 第一个字节保留，第二个字节是地址族
        const family = self.value[1];

        if (family == 0x01) {
            // IPv4
            if (self.value.len < 8) return null;
            const port = std.mem.readInt(u16, self.value[2..4], .big);
            var addr: net.Address = undefined;
            const addr_in = @as(*posix.sockaddr.in, @ptrCast(@alignCast(&addr.any)));
            addr_in.family = posix.AF.INET;
            addr_in.port = std.mem.nativeToBig(u16, port);
            @memcpy(@as(*[4]u8, @ptrCast(&addr_in.addr)), self.value[4..8]);
            return addr;
        } else if (family == 0x02) {
            // IPv6
            if (self.value.len < 20) return null;
            const port = std.mem.readInt(u16, self.value[2..4], .big);
            var addr: net.Address = undefined;
            const addr_in6 = @as(*posix.sockaddr.in6, @ptrCast(@alignCast(&addr.any)));
            addr_in6.family = posix.AF.INET6;
            addr_in6.port = std.mem.nativeToBig(u16, port);
            @memcpy(@as(*[16]u8, @ptrCast(&addr_in6.addr)), self.value[4..20]);
            return addr;
        }

        return null;
    }

    /// 解析 XOR 映射地址属性 (RFC 5389)
    pub fn parseXorMappedAddress(self: *const StunAttribute, transaction_id: [12]u8) ?net.Address {
        if (self.value.len < 8) return null;

        const family = self.value[1];

        if (family == 0x01) {
            // IPv4
            if (self.value.len < 8) return null;

            // 端口 XOR 高 16 位 magic cookie
            const xport = std.mem.readInt(u16, self.value[2..4], .big);
            const port = xport ^ @as(u16, @truncate(STUN_MAGIC_COOKIE >> 16));

            // 地址 XOR magic cookie
            var ip_bytes: [4]u8 = undefined;
            @memcpy(&ip_bytes, self.value[4..8]);
            const magic_bytes = std.mem.toBytes(std.mem.nativeToBig(u32, STUN_MAGIC_COOKIE));
            for (&ip_bytes, magic_bytes) |*b, m| {
                b.* ^= m;
            }

            var addr: net.Address = undefined;
            const addr_in = @as(*posix.sockaddr.in, @ptrCast(@alignCast(&addr.any)));
            addr_in.family = posix.AF.INET;
            addr_in.port = std.mem.nativeToBig(u16, port);
            @memcpy(@as(*[4]u8, @ptrCast(&addr_in.addr)), &ip_bytes);
            return addr;
        } else if (family == 0x02) {
            // IPv6 - XOR with magic cookie + transaction ID
            if (self.value.len < 20) return null;

            const xport = std.mem.readInt(u16, self.value[2..4], .big);
            const port = xport ^ @as(u16, @truncate(STUN_MAGIC_COOKIE >> 16));

            var ip_bytes: [16]u8 = undefined;
            @memcpy(&ip_bytes, self.value[4..20]);

            // XOR with magic cookie (4 bytes) + transaction ID (12 bytes)
            const magic_bytes = std.mem.toBytes(std.mem.nativeToBig(u32, STUN_MAGIC_COOKIE));
            for (ip_bytes[0..4], magic_bytes) |*b, m| {
                b.* ^= m;
            }
            for (ip_bytes[4..16], transaction_id) |*b, t| {
                b.* ^= t;
            }

            var addr: net.Address = undefined;
            const addr_in6 = @as(*posix.sockaddr.in6, @ptrCast(@alignCast(&addr.any)));
            addr_in6.family = posix.AF.INET6;
            addr_in6.port = std.mem.nativeToBig(u16, port);
            @memcpy(@as(*[16]u8, @ptrCast(&addr_in6.addr)), &ip_bytes);
            return addr;
        }

        return null;
    }
};

/// 解析属性结果
const ParsedAttributes = struct {
    mapped_address: ?net.Address,
    changed_address: ?net.Address,
};

/// 解析属性列表
fn parseAttributes(data: []const u8, transaction_id: [12]u8) ParsedAttributes {
    var result = ParsedAttributes{
        .mapped_address = null,
        .changed_address = null,
    };

    var offset: usize = 0;
    while (offset + 4 <= data.len) {
        const attr_type: types.StunAttributeType = @enumFromInt(std.mem.readInt(u16, data[offset..][0..2], .big));
        const attr_len = std.mem.readInt(u16, data[offset + 2 ..][0..2], .big);
        offset += 4;

        if (offset + attr_len > data.len) break;

        const attr = StunAttribute{
            .attr_type = attr_type,
            .length = attr_len,
            .value = data[offset .. offset + attr_len],
        };

        switch (attr_type) {
            .mapped_address => {
                if (result.mapped_address == null) {
                    result.mapped_address = attr.parseMappedAddress();
                }
            },
            .xor_mapped_address => {
                // XOR 映射地址优先
                result.mapped_address = attr.parseXorMappedAddress(transaction_id);
            },
            .changed_address => {
                result.changed_address = attr.parseMappedAddress();
            },
            else => {},
        }

        // 属性需要 4 字节对齐
        const padded_len = (attr_len + 3) & ~@as(u16, 3);
        offset += padded_len;
    }

    return result;
}

/// 构建 CHANGE-REQUEST 属性
fn buildChangeRequestAttribute(change_ip: bool, change_port: bool) [8]u8 {
    var attr: [8]u8 = undefined;
    // 属性类型
    std.mem.writeInt(u16, attr[0..2], @intFromEnum(types.StunAttributeType.change_request), .big);
    // 属性长度
    std.mem.writeInt(u16, attr[2..4], 4, .big);
    // 属性值 (flags)
    const flags: u32 = (@as(u32, if (change_ip) 4 else 0)) | (@as(u32, if (change_port) 2 else 0));
    std.mem.writeInt(u32, attr[4..8], flags, .big);
    return attr;
}

/// STUN 客户端
pub const StunClient = struct {
    const Self = @This();

    /// 服务器地址
    server_addr: net.Address,
    /// 本地地址
    local_addr: net.Address,
    /// 配置
    config: StunConfig,
    /// Socket
    socket: ?posix.socket_t = null,

    /// 创建 STUN 客户端
    pub fn init(server: net.Address, local: net.Address, cfg: StunConfig) Self {
        return Self{
            .server_addr = server,
            .local_addr = local,
            .config = cfg,
        };
    }

    /// 关闭客户端
    pub fn deinit(self: *Self) void {
        if (self.socket) |sock| {
            posix.close(sock);
            self.socket = null;
        }
    }

    /// 连接（创建 socket）
    pub fn connect(self: *Self) !void {
        if (self.socket != null) return;

        self.socket = try net_utils.createReuseUdpSocket(self.local_addr);

        // 设置接收超时
        try net_utils.setRecvTimeout(self.socket.?, self.config.recv_timeout_ms);
    }

    /// 执行 NAT 类型检测 (RFC 3489 算法)
    pub fn query(self: *Self) !StunResult {
        var result = StunResult{};

        // 确保已连接
        try self.connect();

        // Test I: 基本绑定请求
        log.debug("STUN Test I: 发送绑定请求到主服务器", .{});
        const test1_result = try self.test1();
        if (test1_result.mapped_address == null) {
            log.warn("STUN Test I 失败: UDP 可能被阻止", .{});
            result.nat_type = .udp_blocked;
            return result;
        }

        result.public_endpoint = test1_result.mapped_address;
        result.changed_address = test1_result.changed_address;
        result.local_endpoint = self.local_addr;

        // 检查是否服务器支持
        if (test1_result.changed_address == null or
            net_utils.addressEqual(test1_result.changed_address.?, self.server_addr))
        {
            log.warn("STUN 服务器不支持完整的 NAT 检测", .{});
            result.nat_type = .unsupported_server;
            return result;
        }

        // Test II: 请求从不同 IP 和端口回复
        log.debug("STUN Test II: 请求改变 IP 和端口", .{});
        const test2_result = self.test2(test1_result.changed_address.?) catch null;

        // 检查是否有 NAT
        if (net_utils.addressEqual(test1_result.mapped_address.?, self.local_addr)) {
            // 没有 NAT
            if (test2_result == null) {
                log.info("检测到对称 UDP 防火墙", .{});
                result.nat_type = .symmetric_udp_firewall;
            } else {
                log.info("检测到开放网络 (无 NAT)", .{});
                result.nat_type = .open_internet;
            }
            return result;
        }

        // 有 NAT
        if (test2_result != null) {
            log.info("检测到全锥型 NAT", .{});
            result.nat_type = .full_cone;
            return result;
        }

        // Test I' (Test 1-2): 向不同服务器发送请求
        log.debug("STUN Test I': 向备用服务器发送请求", .{});
        const test12_result = try self.test1Alt(test1_result.changed_address.?);

        if (test12_result.mapped_address == null) {
            result.nat_type = .unknown;
            return result;
        }

        // 比较两次映射地址
        if (!net_utils.addressEqual(test12_result.mapped_address.?, test1_result.mapped_address.?)) {
            log.info("检测到对称型 NAT", .{});
            result.nat_type = .symmetric;
            result.public_endpoint = test12_result.mapped_address;
            return result;
        }

        // Test III: 请求从相同 IP 但不同端口回复
        log.debug("STUN Test III: 请求改变端口", .{});
        const test3_result = self.test3() catch null;

        if (test3_result != null) {
            log.info("检测到受限锥型 NAT", .{});
            result.nat_type = .restricted_cone;
        } else {
            log.info("检测到端口受限锥型 NAT", .{});
            result.nat_type = .port_restricted_cone;
        }

        return result;
    }

    /// Test I: 基本绑定请求
    fn test1(self: *Self) !ParsedAttributes {
        var msg = StunMessage{
            .message_type = .binding_request,
            .magic_cookie = if (self.config.use_rfc5389) STUN_MAGIC_COOKIE else 0,
        };
        msg.generateTransactionId();

        return try self.sendAndReceive(&msg, self.server_addr);
    }

    /// Test II: 请求改变 IP 和端口
    fn test2(self: *Self, changed_addr: net.Address) !?ParsedAttributes {
        _ = changed_addr;
        const change_attr = buildChangeRequestAttribute(true, true);

        var msg = StunMessage{
            .message_type = .binding_request,
            .magic_cookie = if (self.config.use_rfc5389) STUN_MAGIC_COOKIE else 0,
            .message_length = @intCast(change_attr.len),
            .attributes = &change_attr,
        };
        msg.generateTransactionId();

        return self.sendAndReceive(&msg, self.server_addr) catch return null;
    }

    /// Test I' (1-2): 向备用服务器发送请求
    fn test1Alt(self: *Self, alt_server: net.Address) !ParsedAttributes {
        var msg = StunMessage{
            .message_type = .binding_request,
            .magic_cookie = if (self.config.use_rfc5389) STUN_MAGIC_COOKIE else 0,
        };
        msg.generateTransactionId();

        return try self.sendAndReceive(&msg, alt_server);
    }

    /// Test III: 请求改变端口
    fn test3(self: *Self) !?ParsedAttributes {
        const change_attr = buildChangeRequestAttribute(false, true);

        var msg = StunMessage{
            .message_type = .binding_request,
            .magic_cookie = if (self.config.use_rfc5389) STUN_MAGIC_COOKIE else 0,
            .message_length = @intCast(change_attr.len),
            .attributes = &change_attr,
        };
        msg.generateTransactionId();

        return self.sendAndReceive(&msg, self.server_addr) catch return null;
    }

    /// 发送请求并接收响应
    fn sendAndReceive(self: *Self, msg: *const StunMessage, target: net.Address) !ParsedAttributes {
        const sock = self.socket orelse return StunError.NetworkError;

        var send_buf: [512]u8 = undefined;
        const send_len = try msg.serialize(&send_buf);

        var retry: u32 = 0;
        while (retry < self.config.retry_count) : (retry += 1) {
            // 发送请求
            _ = posix.sendto(sock, send_buf[0..send_len], 0, &target.any, target.getOsSockLen()) catch {
                continue;
            };

            // 接收响应
            var recv_buf: [512]u8 = undefined;
            var from_addr: posix.sockaddr = undefined;
            var from_len: posix.socklen_t = @sizeOf(posix.sockaddr);

            const recv_len = posix.recvfrom(sock, &recv_buf, 0, &from_addr, &from_len) catch |e| {
                if (e == error.WouldBlock) {
                    log.debug("STUN 请求超时 (重试 {d}/{d})", .{ retry + 1, self.config.retry_count });
                    continue;
                }
                return StunError.NetworkError;
            };

            // 解析响应
            const response = StunMessage.parse(recv_buf[0..recv_len]) catch {
                continue;
            };

            // 验证事务 ID
            if (!msg.isSameTransaction(&response)) {
                continue;
            }

            // 检查响应类型
            if (response.message_type != .binding_response) {
                continue;
            }

            // 解析属性
            return parseAttributes(response.attributes, response.transaction_id);
        }

        return StunError.Timeout;
    }
};

/// 获取公网地址 (简化接口)
pub fn getPublicAddress(server: []const u8, server_port: u16, local_port: u16) !?net.Address {
    const server_addr = net.Address.parseIp4(server, server_port) catch
        return null;

    const local_addr = net.Address.initIp4(.{ 0, 0, 0, 0 }, local_port);

    var client = StunClient.init(server_addr, local_addr, .{});
    defer client.deinit();

    const result = try client.query();
    return result.public_endpoint;
}

/// 检测 NAT 类型 (简化接口)
pub fn detectNatType(server: []const u8, server_port: u16, local_port: u16) !types.NatType {
    const server_addr = net.Address.parseIp4(server, server_port) catch
        return .unknown;

    const local_addr = net.Address.initIp4(.{ 0, 0, 0, 0 }, local_port);

    var client = StunClient.init(server_addr, local_addr, .{});
    defer client.deinit();

    const result = try client.query();
    return result.nat_type;
}

/// 公共 STUN 服务器列表
pub const public_stun_servers = [_][]const u8{
    "stun.l.google.com",
    "stun1.l.google.com",
    "stun2.l.google.com",
    "stun3.l.google.com",
    "stun4.l.google.com",
    "stun.cloudflare.com",
    "stun.stunprotocol.org",
};

test "StunMessage serialize and parse" {
    var msg = StunMessage{
        .message_type = .binding_request,
        .magic_cookie = STUN_MAGIC_COOKIE,
    };
    msg.generateTransactionId();

    var buf: [64]u8 = undefined;
    const len = try msg.serialize(&buf);

    try std.testing.expect(len == STUN_HEADER_SIZE);

    const parsed = try StunMessage.parse(buf[0..len]);
    try std.testing.expect(parsed.message_type == .binding_request);
    try std.testing.expect(msg.isSameTransaction(&parsed));
}
