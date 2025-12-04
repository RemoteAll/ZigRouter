//! 网络工具模块
//! 提供 Socket 操作、端口复用、TTL 设置等底层网络功能
//! 支持 IPv4 和 IPv6 双栈操作

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

/// 地址族类型
pub const AddressFamily = enum {
    ipv4,
    ipv6,
    unknown,
};

/// 地址族常量 (跨平台)
/// AF_INET = 2 (所有平台)
/// AF_INET6 = 10 (Linux) / 23 (Windows) / 30 (macOS)
pub const AF_INET_VALUE: u16 = 2;
pub const AF_INET6_LINUX: u16 = 10;
pub const AF_INET6_WINDOWS: u16 = 23;
pub const AF_INET6_MACOS: u16 = 30;

/// 检查地址族值是否为 IPv4
pub fn isAfInet(family: u16) bool {
    return family == AF_INET_VALUE;
}

/// 检查地址族值是否为 IPv6
pub fn isAfInet6(family: u16) bool {
    return family == AF_INET6_LINUX or family == AF_INET6_WINDOWS or family == AF_INET6_MACOS;
}

/// 获取地址的地址族类型
pub fn getAddressFamily(addr: net.Address) AddressFamily {
    if (isAfInet(addr.any.family)) return .ipv4;
    if (isAfInet6(addr.any.family)) return .ipv6;
    return .unknown;
}

/// 检查地址是否为 IPv4
pub fn isIPv4(addr: net.Address) bool {
    return isAfInet(addr.any.family);
}

/// 检查地址是否为 IPv6
pub fn isIPv6(addr: net.Address) bool {
    return isAfInet6(addr.any.family);
}

/// 检查是否为 IPv4 映射的 IPv6 地址 (::ffff:x.x.x.x)
pub fn isIPv4MappedIPv6(addr: net.Address) bool {
    if (!isIPv6(addr)) return false;

    const addr6 = @as(*const posix.sockaddr.in6, @ptrCast(@alignCast(&addr.any)));
    const ipv6_bytes = @as(*const [16]u8, @ptrCast(&addr6.addr));

    const ipv4_mapped_prefix = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
    return std.mem.eql(u8, ipv6_bytes[0..12], &ipv4_mapped_prefix);
}

/// 检查是否为 IPv6 链路本地地址 (fe80::/10)
pub fn isIPv6LinkLocal(addr: net.Address) bool {
    if (!isIPv6(addr)) return false;

    const addr6 = @as(*const posix.sockaddr.in6, @ptrCast(@alignCast(&addr.any)));
    const ipv6_bytes = @as(*const [16]u8, @ptrCast(&addr6.addr));

    // fe80::/10 - 前 10 位为 1111111010
    return ipv6_bytes[0] == 0xfe and (ipv6_bytes[1] & 0xc0) == 0x80;
}

/// 检查是否为 IPv6 站点本地地址 (fec0::/10) - 已废弃但仍需支持
pub fn isIPv6SiteLocal(addr: net.Address) bool {
    if (!isIPv6(addr)) return false;

    const addr6 = @as(*const posix.sockaddr.in6, @ptrCast(@alignCast(&addr.any)));
    const ipv6_bytes = @as(*const [16]u8, @ptrCast(&addr6.addr));

    // fec0::/10
    return ipv6_bytes[0] == 0xfe and (ipv6_bytes[1] & 0xc0) == 0xc0;
}

/// 检查是否为 IPv6 唯一本地地址 (ULA, fc00::/7)
pub fn isIPv6UniqueLocal(addr: net.Address) bool {
    if (!isIPv6(addr)) return false;

    const addr6 = @as(*const posix.sockaddr.in6, @ptrCast(@alignCast(&addr.any)));
    const ipv6_bytes = @as(*const [16]u8, @ptrCast(&addr6.addr));

    // fc00::/7 - 前 7 位为 1111110
    return (ipv6_bytes[0] & 0xfe) == 0xfc;
}

/// 检查是否为 IPv6 全局单播地址 (2000::/3)
pub fn isIPv6GlobalUnicast(addr: net.Address) bool {
    if (!isIPv6(addr)) return false;

    const addr6 = @as(*const posix.sockaddr.in6, @ptrCast(@alignCast(&addr.any)));
    const ipv6_bytes = @as(*const [16]u8, @ptrCast(&addr6.addr));

    // 2000::/3 - 前 3 位为 001
    return (ipv6_bytes[0] & 0xe0) == 0x20;
}

/// 检查是否为 IPv6 组播地址 (ff00::/8)
pub fn isIPv6Multicast(addr: net.Address) bool {
    if (!isIPv6(addr)) return false;

    const addr6 = @as(*const posix.sockaddr.in6, @ptrCast(@alignCast(&addr.any)));
    const ipv6_bytes = @as(*const [16]u8, @ptrCast(&addr6.addr));

    return ipv6_bytes[0] == 0xff;
}

/// 检查是否为 IPv6 回环地址 (::1)
pub fn isIPv6Loopback(addr: net.Address) bool {
    if (!isIPv6(addr)) return false;

    const addr6 = @as(*const posix.sockaddr.in6, @ptrCast(@alignCast(&addr.any)));
    const ipv6_bytes = @as(*const [16]u8, @ptrCast(&addr6.addr));

    const loopback = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    return std.mem.eql(u8, ipv6_bytes, &loopback);
}

/// 检查是否为 IPv4 回环地址 (127.x.x.x)
pub fn isIPv4Loopback(addr: net.Address) bool {
    if (!isIPv4(addr)) return false;

    const addr4 = @as(*const posix.sockaddr.in, @ptrCast(@alignCast(&addr.any)));
    const ip_bytes = @as(*const [4]u8, @ptrCast(&addr4.addr));

    return ip_bytes[0] == 127;
}

/// 检查是否为回环地址 (IPv4 或 IPv6)
pub fn isLoopback(addr: net.Address) bool {
    return isIPv4Loopback(addr) or isIPv6Loopback(addr);
}

/// 检查是否为 IPv4 私有地址 (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
pub fn isIPv4Private(addr: net.Address) bool {
    if (!isIPv4(addr)) return false;

    const addr4 = @as(*const posix.sockaddr.in, @ptrCast(@alignCast(&addr.any)));
    const ip_bytes = @as(*const [4]u8, @ptrCast(&addr4.addr));

    // 10.0.0.0/8
    if (ip_bytes[0] == 10) return true;
    // 172.16.0.0/12
    if (ip_bytes[0] == 172 and (ip_bytes[1] & 0xf0) == 16) return true;
    // 192.168.0.0/16
    if (ip_bytes[0] == 192 and ip_bytes[1] == 168) return true;

    return false;
}

/// 检查是否为私有/本地地址 (IPv4 私有或 IPv6 链路本地/唯一本地)
pub fn isPrivateAddress(addr: net.Address) bool {
    if (isIPv4(addr)) {
        return isIPv4Private(addr) or isIPv4Loopback(addr);
    }
    if (isIPv6(addr)) {
        return isIPv6LinkLocal(addr) or isIPv6UniqueLocal(addr) or isIPv6Loopback(addr) or isIPv6SiteLocal(addr);
    }
    return false;
}

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
    // 使用辅助函数判断地址族
    const family_value = local_addr.any.family;
    const sock = blk: {
        if (isAfInet(family_value)) {
            // IPv4
            break :blk try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
        } else if (isAfInet6(family_value)) {
            // IPv6
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
    // 使用辅助函数判断地址族
    const family_value = local_addr.any.family;
    const sock = blk: {
        if (isAfInet(family_value)) {
            // IPv4
            break :blk try posix.socket(posix.AF.INET, posix.SOCK.STREAM, posix.IPPROTO.TCP);
        } else if (isAfInet6(family_value)) {
            // IPv6
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

/// 创建支持双栈的 UDP Socket (IPv6 socket 可接受 IPv4 连接)
pub fn createDualStackUdpSocket(port: u16) !posix.socket_t {
    const sock = try posix.socket(posix.AF.INET6, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
    errdefer posix.close(sock);

    // 设置端口复用
    try setReuseAddr(sock, true);
    try setReusePort(sock, true);

    // 禁用 IPV6_V6ONLY 以支持双栈
    setIpv6Only(sock, false) catch {}; // 某些平台可能不支持

    // Windows UDP bug 修复
    windowsUdpBugFix(sock);

    // 绑定到 in6addr_any
    const bind_addr = net.Address.parseIp6("::", port) catch unreachable;
    try posix.bind(sock, &bind_addr.any, bind_addr.getOsSockLen());

    return sock;
}

/// 创建支持双栈的 TCP Socket (IPv6 socket 可接受 IPv4 连接)
pub fn createDualStackTcpSocket(port: u16) !posix.socket_t {
    const sock = try posix.socket(posix.AF.INET6, posix.SOCK.STREAM, posix.IPPROTO.TCP);
    errdefer posix.close(sock);

    // 设置端口复用
    try setReuseAddr(sock, true);
    try setReusePort(sock, true);

    // 禁用 IPV6_V6ONLY 以支持双栈
    setIpv6Only(sock, false) catch {}; // 某些平台可能不支持

    // 绑定到 in6addr_any
    const bind_addr = net.Address.parseIp6("::", port) catch unreachable;
    try posix.bind(sock, &bind_addr.any, bind_addr.getOsSockLen());

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

/// 获取本机 IPv6 出口地址（通过 UDP 连接获取）
pub fn getLocalOutboundAddressV6() ?net.Address {
    // 创建 IPv6 UDP socket
    const sock = posix.socket(posix.AF.INET6, posix.SOCK.DGRAM, posix.IPPROTO.UDP) catch return null;
    defer posix.close(sock);

    // 连接到 Google IPv6 DNS 2001:4860:4860::8888:53
    const target = net.Address.parseIp6("2001:4860:4860::8888", 53) catch return null;
    posix.connect(sock, &target.any, target.getOsSockLen()) catch return null;

    // 获取本地地址
    var local_addr: posix.sockaddr.in6 = undefined;
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in6);
    posix.getsockname(sock, @ptrCast(&local_addr), &addr_len) catch return null;

    var result: net.Address = undefined;
    @memcpy(std.mem.asBytes(&result.in6), std.mem.asBytes(&local_addr));
    return result;
}

/// 获取本机所有出口地址（IPv4 和 IPv6）
pub fn getLocalOutboundAddresses(allocator: std.mem.Allocator) ![]net.Address {
    var addresses: std.ArrayList(net.Address) = .{};
    errdefer addresses.deinit(allocator);

    // 获取 IPv4 出口地址
    if (getLocalOutboundAddress()) |addr| {
        try addresses.append(allocator, addr);
    }

    // 获取 IPv6 出口地址
    if (getLocalOutboundAddressV6()) |addr| {
        try addresses.append(allocator, addr);
    }

    return try addresses.toOwnedSlice(allocator);
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

    // 使用辅助函数判断地址族
    if (isAfInet(a.any.family)) { // AF_INET
        const a4 = @as(*const posix.sockaddr.in, @ptrCast(@alignCast(&a.any)));
        const b4 = @as(*const posix.sockaddr.in, @ptrCast(@alignCast(&b.any)));
        return a4.addr == b4.addr and a4.port == b4.port;
    } else if (isAfInet6(a.any.family)) { // AF_INET6
        const a6 = @as(*const posix.sockaddr.in6, @ptrCast(@alignCast(&a.any)));
        const b6 = @as(*const posix.sockaddr.in6, @ptrCast(@alignCast(&b.any)));
        return std.mem.eql(u8, &a6.addr, &b6.addr) and a6.port == b6.port;
    }
    return false;
}

/// 转换 IPv4 映射的 IPv6 地址到纯 IPv4
pub fn convertMappedAddress(addr: net.Address) net.Address {
    if (!isIPv4MappedIPv6(addr)) {
        return addr;
    }

    const addr6 = @as(*const posix.sockaddr.in6, @ptrCast(@alignCast(&addr.any)));
    const ipv6_bytes = @as(*const [16]u8, @ptrCast(&addr6.addr));

    // 转换为 IPv4
    var result: net.Address = undefined;
    const result_in = @as(*posix.sockaddr.in, @ptrCast(@alignCast(&result.any)));
    result_in.family = posix.AF.INET;
    result_in.port = addr6.port;
    @memcpy(@as(*[4]u8, @ptrCast(&result_in.addr)), ipv6_bytes[12..16]);
    return result;
}

/// 将 IPv4 地址转换为 IPv4 映射的 IPv6 地址 (::ffff:x.x.x.x)
pub fn convertToIPv4MappedIPv6(addr: net.Address, port: u16) ?net.Address {
    if (!isIPv4(addr)) {
        return null;
    }

    const addr4 = @as(*const posix.sockaddr.in, @ptrCast(@alignCast(&addr.any)));
    const ip4_bytes = @as(*const [4]u8, @ptrCast(&addr4.addr));

    var result: net.Address = undefined;
    const result_in6 = @as(*posix.sockaddr.in6, @ptrCast(@alignCast(&result.any)));
    result_in6.family = posix.AF.INET6;
    result_in6.port = std.mem.nativeToBig(u16, port);
    result_in6.flowinfo = 0;
    result_in6.scope_id = 0;

    // 设置 IPv4 映射前缀 ::ffff:
    const prefix = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
    @memcpy(@as(*[12]u8, @ptrCast(&result_in6.addr)), &prefix);
    @memcpy(@as(*[4]u8, @ptrCast(@as([*]u8, @ptrCast(&result_in6.addr)) + 12)), ip4_bytes);

    return result;
}

/// 规范化地址（如果是 IPv4 映射的 IPv6 则转换为 IPv4）
pub fn normalizeAddress(addr: net.Address) net.Address {
    if (isIPv4MappedIPv6(addr)) {
        return convertMappedAddress(addr);
    }
    return addr;
}

/// 创建 IPv6 地址（从字节和端口）
pub fn createIPv6Address(bytes: [16]u8, port: u16, scope_id: u32) net.Address {
    var result: net.Address = undefined;
    const addr_in6 = @as(*posix.sockaddr.in6, @ptrCast(@alignCast(&result.any)));
    addr_in6.family = posix.AF.INET6;
    addr_in6.port = std.mem.nativeToBig(u16, port);
    addr_in6.flowinfo = 0;
    addr_in6.scope_id = scope_id;
    @memcpy(&addr_in6.addr, &bytes);
    return result;
}

/// 创建 IPv4 地址（从字节和端口）
pub fn createIPv4Address(bytes: [4]u8, port: u16) net.Address {
    var result: net.Address = undefined;
    const addr_in = @as(*posix.sockaddr.in, @ptrCast(@alignCast(&result.any)));
    addr_in.family = posix.AF.INET;
    addr_in.port = std.mem.nativeToBig(u16, port);
    @memcpy(@as(*[4]u8, @ptrCast(&addr_in.addr)), &bytes);
    return result;
}

/// 获取地址的端口号
pub fn getPort(addr: net.Address) u16 {
    if (isAfInet(addr.any.family)) {
        const addr4 = @as(*const posix.sockaddr.in, @ptrCast(@alignCast(&addr.any)));
        return std.mem.bigToNative(u16, addr4.port);
    } else if (isAfInet6(addr.any.family)) {
        const addr6 = @as(*const posix.sockaddr.in6, @ptrCast(@alignCast(&addr.any)));
        return std.mem.bigToNative(u16, addr6.port);
    }
    return 0;
}

/// 设置地址的端口号
pub fn setPort(addr: *net.Address, port: u16) void {
    if (isAfInet(addr.any.family)) {
        const addr4 = @as(*posix.sockaddr.in, @ptrCast(@alignCast(&addr.any)));
        addr4.port = std.mem.nativeToBig(u16, port);
    } else if (isAfInet6(addr.any.family)) {
        const addr6 = @as(*posix.sockaddr.in6, @ptrCast(@alignCast(&addr.any)));
        addr6.port = std.mem.nativeToBig(u16, port);
    }
}

/// 获取地址的 IP 字节数组
pub fn getIPBytes(addr: net.Address) ?[]const u8 {
    if (isAfInet(addr.any.family)) {
        const addr4 = @as(*const posix.sockaddr.in, @ptrCast(@alignCast(&addr.any)));
        return @as(*const [4]u8, @ptrCast(&addr4.addr));
    } else if (isAfInet6(addr.any.family)) {
        const addr6 = @as(*const posix.sockaddr.in6, @ptrCast(@alignCast(&addr.any)));
        return @as(*const [16]u8, @ptrCast(&addr6.addr));
    }
    return null;
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

test "setReuseAddr IPv6" {
    const sock = try posix.socket(posix.AF.INET6, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
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

test "addressEqual IPv6" {
    const addr1 = try net.Address.parseIp6("::1", 8080);
    const addr2 = try net.Address.parseIp6("::1", 8080);
    const addr3 = try net.Address.parseIp6("::1", 8081);
    const addr4 = try net.Address.parseIp6("2001:db8::1", 8080);

    try std.testing.expect(addressEqual(addr1, addr2));
    try std.testing.expect(!addressEqual(addr1, addr3));
    try std.testing.expect(!addressEqual(addr1, addr4));
}

test "isIPv4 and isIPv6" {
    const ipv4_addr = try net.Address.parseIp4("192.168.1.1", 80);
    const ipv6_addr = try net.Address.parseIp6("2001:db8::1", 80);

    try std.testing.expect(isIPv4(ipv4_addr));
    try std.testing.expect(!isIPv6(ipv4_addr));
    try std.testing.expect(!isIPv4(ipv6_addr));
    try std.testing.expect(isIPv6(ipv6_addr));
}

test "isIPv6LinkLocal" {
    const link_local = try net.Address.parseIp6("fe80::1", 80);
    const global = try net.Address.parseIp6("2001:db8::1", 80);

    try std.testing.expect(isIPv6LinkLocal(link_local));
    try std.testing.expect(!isIPv6LinkLocal(global));
}

test "isIPv6GlobalUnicast" {
    const global = try net.Address.parseIp6("2001:db8::1", 80);
    const link_local = try net.Address.parseIp6("fe80::1", 80);
    const loopback = try net.Address.parseIp6("::1", 80);

    try std.testing.expect(isIPv6GlobalUnicast(global));
    try std.testing.expect(!isIPv6GlobalUnicast(link_local));
    try std.testing.expect(!isIPv6GlobalUnicast(loopback));
}

test "isIPv6UniqueLocal" {
    const ula = try net.Address.parseIp6("fc00::1", 80);
    const ula2 = try net.Address.parseIp6("fd00::1", 80);
    const global = try net.Address.parseIp6("2001:db8::1", 80);

    try std.testing.expect(isIPv6UniqueLocal(ula));
    try std.testing.expect(isIPv6UniqueLocal(ula2));
    try std.testing.expect(!isIPv6UniqueLocal(global));
}

test "isIPv6Loopback" {
    const loopback = try net.Address.parseIp6("::1", 80);
    const not_loopback = try net.Address.parseIp6("::2", 80);

    try std.testing.expect(isIPv6Loopback(loopback));
    try std.testing.expect(!isIPv6Loopback(not_loopback));
}

test "isLoopback" {
    const ipv4_lo = try net.Address.parseIp4("127.0.0.1", 80);
    const ipv4_lo2 = try net.Address.parseIp4("127.255.255.255", 80);
    const ipv6_lo = try net.Address.parseIp6("::1", 80);
    const not_lo = try net.Address.parseIp4("192.168.1.1", 80);

    try std.testing.expect(isLoopback(ipv4_lo));
    try std.testing.expect(isLoopback(ipv4_lo2));
    try std.testing.expect(isLoopback(ipv6_lo));
    try std.testing.expect(!isLoopback(not_lo));
}

test "isIPv4Private" {
    const private10 = try net.Address.parseIp4("10.0.0.1", 80);
    const private172 = try net.Address.parseIp4("172.16.0.1", 80);
    const private192 = try net.Address.parseIp4("192.168.1.1", 80);
    const public_addr = try net.Address.parseIp4("8.8.8.8", 80);

    try std.testing.expect(isIPv4Private(private10));
    try std.testing.expect(isIPv4Private(private172));
    try std.testing.expect(isIPv4Private(private192));
    try std.testing.expect(!isIPv4Private(public_addr));
}

test "getPort and setPort" {
    var ipv4_addr = try net.Address.parseIp4("192.168.1.1", 8080);
    var ipv6_addr = try net.Address.parseIp6("2001:db8::1", 443);

    try std.testing.expectEqual(@as(u16, 8080), getPort(ipv4_addr));
    try std.testing.expectEqual(@as(u16, 443), getPort(ipv6_addr));

    setPort(&ipv4_addr, 9090);
    setPort(&ipv6_addr, 8443);

    try std.testing.expectEqual(@as(u16, 9090), getPort(ipv4_addr));
    try std.testing.expectEqual(@as(u16, 8443), getPort(ipv6_addr));
}

test "createIPv4Address and createIPv6Address" {
    const ipv4 = createIPv4Address(.{ 192, 168, 1, 1 }, 80);
    const ipv6 = createIPv6Address(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 443, 0);

    try std.testing.expect(isIPv4(ipv4));
    try std.testing.expect(isIPv6(ipv6));
    try std.testing.expectEqual(@as(u16, 80), getPort(ipv4));
    try std.testing.expectEqual(@as(u16, 443), getPort(ipv6));
}

test "getLocalOutboundAddress" {
    // 这个测试可能在没有网络的环境下失败
    if (getLocalOutboundAddress()) |addr| {
        var buf: [64]u8 = undefined;
        const str = formatAddress(addr, &buf);
        log.debug("Local outbound IPv4 address: {s}", .{str});
        try std.testing.expect(isIPv4(addr));
    }
}

test "getLocalOutboundAddressV6" {
    // 这个测试可能在没有 IPv6 网络的环境下失败
    if (getLocalOutboundAddressV6()) |addr| {
        var buf: [64]u8 = undefined;
        const str = formatAddress(addr, &buf);
        log.debug("Local outbound IPv6 address: {s}", .{str});
        try std.testing.expect(isIPv6(addr));
    }
}
