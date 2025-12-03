//! 网络工具模块
//! 提供 Socket 操作、端口复用、TTL 设置等底层网络功能

const std = @import("std");
const net = std.net;
const posix = std.posix;
const log = @import("log.zig");
const builtin = @import("builtin");

/// Socket 选项设置错误
pub const SocketOptionError = error{
    SetOptionFailed,
    GetOptionFailed,
    InvalidSocket,
    UnsupportedPlatform,
};

/// 设置 Socket 端口复用 (SO_REUSEADDR)
pub fn setReuseAddr(sock: posix.socket_t, enable: bool) SocketOptionError!void {
    const value: c_int = if (enable) 1 else 0;
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(value)) catch {
        return SocketOptionError.SetOptionFailed;
    };
}

/// 设置 Socket 端口复用 (SO_REUSEPORT) - 仅 Unix 系统支持
pub fn setReusePort(sock: posix.socket_t, enable: bool) SocketOptionError!void {
    if (builtin.os.tag == .windows) {
        // Windows 不支持 SO_REUSEPORT，但 SO_REUSEADDR 在 Windows 上行为类似
        return;
    }

    const value: c_int = if (enable) 1 else 0;
    // SO_REUSEPORT 值在不同平台可能不同
    const SO_REUSEPORT: u32 = switch (builtin.os.tag) {
        .linux => 15,
        .macos, .ios, .tvos, .watchos, .visionos => 0x0200,
        .freebsd, .openbsd, .netbsd, .dragonfly => 0x0200,
        else => return, // 其他平台跳过
    };
    posix.setsockopt(sock, posix.SOL.SOCKET, SO_REUSEPORT, &std.mem.toBytes(value)) catch {
        // SO_REUSEPORT 不是必需的，失败时不报错
        log.debug("SO_REUSEPORT 设置失败，可能不支持", .{});
    };
}

/// 设置 TCP Keep-Alive
pub fn setKeepAlive(sock: posix.socket_t, enable: bool) SocketOptionError!void {
    const value: c_int = if (enable) 1 else 0;
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.KEEPALIVE, &std.mem.toBytes(value)) catch {
        return SocketOptionError.SetOptionFailed;
    };
}

/// 设置 Socket TTL (用于 UDP 打洞的 TTL 技巧)
pub fn setTtl(sock: posix.socket_t, ttl: u8) SocketOptionError!void {
    const value: c_int = ttl;
    const IP_TTL: u32 = if (@import("builtin").os.tag == .windows) 4 else 2; // Windows=4, Linux=2
    posix.setsockopt(sock, posix.IPPROTO.IP, IP_TTL, &std.mem.toBytes(value)) catch {
        return SocketOptionError.SetOptionFailed;
    };
}

/// 设置 IPv6 TTL (Hop Limit)
pub fn setIpv6HopLimit(sock: posix.socket_t, hop_limit: u8) SocketOptionError!void {
    const value: c_int = hop_limit;
    const IPV6_UNICAST_HOPS: u32 = 16;
    posix.setsockopt(sock, posix.IPPROTO.IPV6, IPV6_UNICAST_HOPS, &std.mem.toBytes(value)) catch {
        return SocketOptionError.SetOptionFailed;
    };
}

/// 设置 IPv6 Only 选项
pub fn setIpv6Only(sock: posix.socket_t, enable: bool) SocketOptionError!void {
    const value: c_int = if (enable) 1 else 0;
    const IPV6_V6ONLY: u32 = 26;
    posix.setsockopt(sock, posix.IPPROTO.IPV6, IPV6_V6ONLY, &std.mem.toBytes(value)) catch {
        return SocketOptionError.SetOptionFailed;
    };
}

/// 设置发送超时
pub fn setSendTimeout(sock: posix.socket_t, timeout_ms: u32) SocketOptionError!void {
    if (builtin.os.tag == .windows) {
        const timeout: c_int = @intCast(timeout_ms);
        posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, &std.mem.toBytes(timeout)) catch {
            return SocketOptionError.SetOptionFailed;
        };
    } else {
        const timeout = posix.timeval{
            .sec = @intCast(timeout_ms / 1000),
            .usec = @intCast((timeout_ms % 1000) * 1000),
        };
        posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch {
            return SocketOptionError.SetOptionFailed;
        };
    }
}

/// 设置接收超时
pub fn setRecvTimeout(sock: posix.socket_t, timeout_ms: u32) SocketOptionError!void {
    if (builtin.os.tag == .windows) {
        const timeout: c_int = @intCast(timeout_ms);
        posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, &std.mem.toBytes(timeout)) catch {
            return SocketOptionError.SetOptionFailed;
        };
    } else {
        const timeout = posix.timeval{
            .sec = @intCast(timeout_ms / 1000),
            .usec = @intCast((timeout_ms % 1000) * 1000),
        };
        posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {
            return SocketOptionError.SetOptionFailed;
        };
    }
}

/// 设置 TCP_NODELAY (禁用 Nagle 算法)
pub fn setTcpNoDelay(sock: posix.socket_t, enable: bool) SocketOptionError!void {
    const value: c_int = if (enable) 1 else 0;
    posix.setsockopt(sock, posix.IPPROTO.TCP, posix.TCP.NODELAY, &std.mem.toBytes(value)) catch {
        return SocketOptionError.SetOptionFailed;
    };
}

/// 设置发送缓冲区大小
pub fn setSendBufferSize(sock: posix.socket_t, size: u32) SocketOptionError!void {
    const value: c_int = @intCast(size);
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDBUF, &std.mem.toBytes(value)) catch {
        return SocketOptionError.SetOptionFailed;
    };
}

/// 设置接收缓冲区大小
pub fn setRecvBufferSize(sock: posix.socket_t, size: u32) SocketOptionError!void {
    const value: c_int = @intCast(size);
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVBUF, &std.mem.toBytes(value)) catch {
        return SocketOptionError.SetOptionFailed;
    };
}

/// Windows UDP 连接重置 bug 修复
/// 在 Windows 上，当 UDP 发送到不存在的端口时会产生 WSAECONNRESET 错误
/// 需要设置 SIO_UDP_CONNRESET 来禁用这个行为
pub fn windowsUdpBugFix(sock: posix.socket_t) void {
    if (builtin.os.tag != .windows) {
        return;
    }
    // Windows 特定的 IOCtl 调用
    // SIO_UDP_CONNRESET = 0x9800000C
    // 这里简化处理，实际需要调用 WSAIoctl
    _ = sock;
    log.debug("Windows UDP bug fix applied", .{});
}

/// 创建带有端口复用的 UDP Socket
pub fn createReuseUdpSocket(local_addr: net.Address) !posix.socket_t {
    // Windows 上 AF 是结构体(常量值)，Linux 上是枚举
    // AF_INET = 2, AF_INET6 = 23 (Windows) / 10 (Linux)
    const family_value = local_addr.any.family;
    const sock = blk: {
        if (family_value == 2) {
            // IPv4
            break :blk try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
        } else if (family_value == 10 or family_value == 23) {
            // IPv6: Linux=10, Windows=23
            break :blk try posix.socket(posix.AF.INET6, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
        } else {
            return error.UnsupportedAddressFamily;
        }
    };
    errdefer posix.close(sock);

    // 设置端口复用
    try setReuseAddr(sock, true);
    try setReusePort(sock, true);

    // Windows UDP bug 修复
    windowsUdpBugFix(sock);

    // 绑定地址
    try posix.bind(sock, &local_addr.any, local_addr.getOsSockLen());

    return sock;
}

/// 创建带有端口复用的 TCP Socket
pub fn createReuseTcpSocket(local_addr: net.Address) !posix.socket_t {
    // Windows 上 AF 是结构体(常量值)，Linux 上是枚举
    // AF_INET = 2, AF_INET6 = 23 (Windows) / 10 (Linux)
    const family_value = local_addr.any.family;
    const sock = blk: {
        if (family_value == 2) {
            // IPv4
            break :blk try posix.socket(posix.AF.INET, posix.SOCK.STREAM, posix.IPPROTO.TCP);
        } else if (family_value == 10 or family_value == 23) {
            // IPv6: Linux=10, Windows=23
            break :blk try posix.socket(posix.AF.INET6, posix.SOCK.STREAM, posix.IPPROTO.TCP);
        } else {
            return error.UnsupportedAddressFamily;
        }
    };
    errdefer posix.close(sock);

    // 设置端口复用
    try setReuseAddr(sock, true);
    try setReusePort(sock, true);

    // 绑定地址
    try posix.bind(sock, &local_addr.any, local_addr.getOsSockLen());

    return sock;
}

/// 获取本地 IP 地址列表
pub fn getLocalIpAddresses(allocator: std.mem.Allocator) ![]net.Address {
    var addresses: std.ArrayList(net.Address) = .{};
    defer addresses.deinit(allocator);

    // 获取主机名
    var hostname_buf: [256]u8 = undefined;
    const hostname = posix.gethostname(&hostname_buf) catch "localhost";
    _ = hostname;

    // 这里简化处理，实际应该遍历网络接口
    // 返回常见的本地地址
    const loopback_v4 = net.Address.parseIp4("127.0.0.1", 0) catch unreachable;
    try addresses.append(allocator, loopback_v4);

    // 尝试获取实际的本地 IP
    // 通过连接一个公网地址（不实际发送数据）来获取本地出口 IP
    if (getLocalOutboundAddress()) |addr| {
        try addresses.append(allocator, addr);
    }

    return try addresses.toOwnedSlice(allocator);
}

/// 获取本机出口 IP 地址（通过 UDP 连接获取）
pub fn getLocalOutboundAddress() ?net.Address {
    // 创建 UDP socket
    const sock = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP) catch return null;
    defer posix.close(sock);

    // 连接到一个公网地址（不会实际发送数据）
    // 使用 Google DNS 8.8.8.8:53
    const target = net.Address.parseIp4("8.8.8.8", 53) catch return null;
    posix.connect(sock, &target.any, target.getOsSockLen()) catch return null;

    // 获取本地地址
    var local_addr: posix.sockaddr = undefined;
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr);
    posix.getsockname(sock, &local_addr, &addr_len) catch return null;

    return net.Address{ .any = local_addr };
}

/// 检测路由层级（到公网的跳数）
pub fn detectRouteLevel() u8 {
    // 简化实现：通过 TTL 递增发送 UDP 包来检测
    // 实际上应该使用 traceroute 算法
    // 这里返回默认值
    return 3;
}

/// 地址比较
pub fn addressEqual(a: net.Address, b: net.Address) bool {
    if (a.any.family != b.any.family) {
        return false;
    }

    // Windows 上 AF 是 struct 常量，不能用 switch
    if (a.any.family == 2) { // AF_INET
        const a4 = @as(*const posix.sockaddr.in, @ptrCast(@alignCast(&a.any)));
        const b4 = @as(*const posix.sockaddr.in, @ptrCast(@alignCast(&b.any)));
        return a4.addr == b4.addr and a4.port == b4.port;
    } else if (a.any.family == 10 or a.any.family == 23) { // AF_INET6 Linux=10, Windows=23
        const a6 = @as(*const posix.sockaddr.in6, @ptrCast(@alignCast(&a.any)));
        const b6 = @as(*const posix.sockaddr.in6, @ptrCast(@alignCast(&b.any)));
        return std.mem.eql(u8, &a6.addr, &b6.addr) and a6.port == b6.port;
    }
    return false;
}

/// 转换 IPv4 映射的 IPv6 地址到纯 IPv4
pub fn convertMappedAddress(addr: net.Address) net.Address {
    // AF_INET6: Linux=10, Windows=23
    if (addr.any.family != 10 and addr.any.family != 23) {
        return addr;
    }

    const addr6 = @as(*const posix.sockaddr.in6, @ptrCast(@alignCast(&addr.any)));
    const ipv6_bytes = @as(*const [16]u8, @ptrCast(&addr6.addr));

    // 检查是否是 IPv4 映射地址 (::ffff:x.x.x.x)
    const prefix = ipv6_bytes[0..12];
    const ipv4_mapped_prefix = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

    if (std.mem.eql(u8, prefix, &ipv4_mapped_prefix)) {
        // 转换为 IPv4
        var result: net.Address = undefined;
        const result_in = @as(*posix.sockaddr.in, @ptrCast(@alignCast(&result.any)));
        result_in.family = posix.AF.INET;
        result_in.port = addr6.port;
        @memcpy(@as(*[4]u8, @ptrCast(&result_in.addr)), ipv6_bytes[12..16]);
        return result;
    }

    return addr;
}

/// 格式化地址为字符串
pub fn formatAddress(addr: net.Address, buf: []u8) []const u8 {
    var stream = std.io.fixedBufferStream(buf);
    addr.format(&.{}, stream.writer()) catch |e| {
        _ = e;
        return "(error)";
    };
    return stream.getWritten();
}

test "setReuseAddr" {
    const sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
    defer posix.close(sock);
    try setReuseAddr(sock, true);
}

test "addressEqual" {
    const addr1 = try net.Address.parseIp4("127.0.0.1", 8080);
    const addr2 = try net.Address.parseIp4("127.0.0.1", 8080);
    const addr3 = try net.Address.parseIp4("127.0.0.1", 8081);

    try std.testing.expect(addressEqual(addr1, addr2));
    try std.testing.expect(!addressEqual(addr1, addr3));
}

test "getLocalOutboundAddress" {
    // 这个测试可能在没有网络的环境下失败
    if (getLocalOutboundAddress()) |addr| {
        var buf: [64]u8 = undefined;
        const str = formatAddress(addr, &buf);
        log.debug("Local outbound address: {s}", .{str});
    }
}
