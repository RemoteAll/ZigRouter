//! 日志模块
//! 提供详细的打洞过程日志，包含 NAT 类型、IP、端口等信息
//! 使用 zzig 的 Logger 模块，支持自动时区转换和服务器时间同步

const std = @import("std");
const types = @import("types.zig");
const zzig = @import("zzig");

/// 日志级别（兼容旧 API）
pub const LogLevel = zzig.Logger.Level;

/// 日志配置（兼容旧 API）
pub const LogConfig = struct {
    /// 最小日志级别
    min_level: LogLevel = .debug,
};

/// 全局日志配置
pub var config = LogConfig{};

/// 设置日志级别
pub fn setLevel(level: LogLevel) void {
    config.min_level = level;
    zzig.Logger.setLevel(level);
}

/// 设置服务器时间偏移量（毫秒）
/// offset_ms: 服务器时间与本地时间的差值（毫秒）
/// 设置后日志时间戳会使用校准后的时间
pub fn setServerTimeOffset(offset_ms: i64) void {
    zzig.Logger.setTimeOffset(offset_ms);
}

/// 获取服务器时间偏移量（毫秒）
pub fn getServerTimeOffset() i64 {
    return zzig.Logger.getTimeOffset();
}

/// 启用线程安全模式
pub fn enableThreadSafe() void {
    zzig.Logger.enableThreadSafe();
}

/// 调试日志
pub fn debug(comptime format: []const u8, args: anytype) void {
    zzig.Logger.debug(format, args);
}

/// 信息日志
pub fn info(comptime format: []const u8, args: anytype) void {
    zzig.Logger.info(format, args);
}

/// 警告日志
pub fn warn(comptime format: []const u8, args: anytype) void {
    zzig.Logger.warn(format, args);
}

/// 错误日志
pub fn err(comptime format: []const u8, args: anytype) void {
    zzig.Logger.err(format, args);
}

/// 格式化网络地址为可读字符串
pub fn formatAddress(addr: std.net.Address) [64]u8 {
    var buf: [64]u8 = undefined;
    @memset(&buf, 0);

    // 手动格式化 IP:端口
    switch (addr.any.family) {
        std.posix.AF.INET => {
            const ip_bytes = @as(*const [4]u8, @ptrCast(&addr.in.sa.addr));
            const port = std.mem.bigToNative(u16, addr.in.sa.port);
            _ = std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}:{d}", .{
                ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3], port,
            }) catch {};
        },
        std.posix.AF.INET6 => {
            const port = std.mem.bigToNative(u16, addr.in6.sa.port);
            _ = std.fmt.bufPrint(&buf, "[IPv6]:{d}", .{port}) catch {};
        },
        else => {
            @memcpy(buf[0..9], "<unknown>");
        },
    }
    return buf;
}

/// 打洞相关的专用日志函数
/// 记录打洞开始
pub fn logPunchStart(transport: types.TransportType, direction: types.TunnelDirection, local: types.EndpointInfo, remote: types.EndpointInfo) void {
    info("========== 打洞开始 ==========", .{});
    info("传输方式: {s} ({s})", .{ transport.name(), transport.label() });
    info("方向: {s}", .{direction.toString()});
    info("本机信息:", .{});
    info("  - 机器ID: {s}", .{if (local.machine_id.len > 0) local.machine_id else "(未设置)"});
    info("  - 机器名: {s}", .{if (local.machine_name.len > 0) local.machine_name else "(未设置)"});
    info("  - NAT类型: {s}", .{local.nat_type.description()});
    const local_local_str = formatAddress(local.local);
    info("  - 本地地址: {s}", .{std.mem.sliceTo(&local_local_str, 0)});
    if (local.remote) |r| {
        const local_remote_str = formatAddress(r);
        info("  - 外网地址: {s}", .{std.mem.sliceTo(&local_remote_str, 0)});
    }
    info("  - 路由层级: {d}", .{local.route_level});
    if (local.port_map_wan != 0) {
        info("  - 端口映射(外网): {d}", .{local.port_map_wan});
        info("  - 端口映射(内网): {d}", .{local.port_map_lan});
    }
    info("对端信息:", .{});
    info("  - 机器ID: {s}", .{if (remote.machine_id.len > 0) remote.machine_id else "(未设置)"});
    info("  - 机器名: {s}", .{if (remote.machine_name.len > 0) remote.machine_name else "(未设置)"});
    info("  - NAT类型: {s}", .{remote.nat_type.description()});
    const remote_local_str = formatAddress(remote.local);
    info("  - 本地地址: {s}", .{std.mem.sliceTo(&remote_local_str, 0)});
    if (remote.remote) |r| {
        const remote_remote_str = formatAddress(r);
        info("  - 外网地址: {s}", .{std.mem.sliceTo(&remote_remote_str, 0)});
    }
    info("  - 路由层级: {d}", .{remote.route_level});
    info("==============================", .{});
}

/// 记录打洞成功
pub fn logPunchSuccess(transport: types.TransportType, connection: types.TunnelConnectionInfo) void {
    info("========== 打洞成功 ==========", .{});
    info("传输方式: {s}", .{transport.name()});
    info("远程机器: {s} ({s})", .{
        if (connection.remote_machine_id.len > 0) connection.remote_machine_id else "(未知)",
        if (connection.remote_machine_name.len > 0) connection.remote_machine_name else "(未知)",
    });
    const remote_ep_str = formatAddress(connection.remote_endpoint);
    info("远程端点: {s}", .{std.mem.sliceTo(&remote_ep_str, 0)});
    info("隧道类型: {s}", .{connection.tunnel_type.toString()});
    info("模式: {s}", .{connection.mode.toString()});
    info("协议: {s}", .{connection.protocol_type.toString()});
    info("SSL: {s}", .{if (connection.ssl) "是" else "否"});
    info("==============================", .{});
}

/// 记录打洞失败
pub fn logPunchFailed(transport: types.TransportType, reason: []const u8) void {
    err("========== 打洞失败 ==========", .{});
    err("传输方式: {s}", .{transport.name()});
    err("失败原因: {s}", .{reason});
    err("==============================", .{});
}

/// 记录 NAT 类型检测结果
pub fn logNatDetection(nat_type: types.NatType, local_addr: std.net.Address, public_addr: ?std.net.Address) void {
    info("========= NAT 检测结果 =========", .{});
    info("NAT 类型: {s}", .{nat_type.description()});
    const local_str = formatAddress(local_addr);
    info("本地地址: {s}", .{std.mem.sliceTo(&local_str, 0)});
    if (public_addr) |addr| {
        const pub_str = formatAddress(addr);
        info("公网地址: {s}", .{std.mem.sliceTo(&pub_str, 0)});
    } else {
        info("公网地址: (未检测到)", .{});
    }
    info("================================", .{});
}

/// 记录发送 TTL 包
pub fn logSendTtl(target: std.net.Address, ttl: u8) void {
    const addr_str = formatAddress(target);
    debug("发送 TTL 包 -> {s}, TTL={d}", .{ std.mem.sliceTo(&addr_str, 0), ttl });
}

/// 记录收到认证包
pub fn logRecvAuth(from: std.net.Address) void {
    const addr_str = formatAddress(from);
    debug("收到认证包 <- {s}", .{std.mem.sliceTo(&addr_str, 0)});
}

/// 记录连接尝试
pub fn logConnectAttempt(target: std.net.Address, attempt: u32) void {
    const addr_str = formatAddress(target);
    debug("尝试连接 -> {s} (第 {d} 次)", .{ std.mem.sliceTo(&addr_str, 0), attempt });
}

test "log level" {
    // 测试日志级别
    try std.testing.expect(@intFromEnum(LogLevel.debug) < @intFromEnum(LogLevel.info));
    try std.testing.expect(@intFromEnum(LogLevel.info) < @intFromEnum(LogLevel.warn));
    try std.testing.expect(@intFromEnum(LogLevel.warn) < @intFromEnum(LogLevel.err));
}
