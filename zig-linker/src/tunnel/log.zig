//! 日志模块
//! 提供详细的打洞过程日志，包含 NAT 类型、IP、端口等信息

const std = @import("std");
const types = @import("types.zig");

/// 日志级别
pub const LogLevel = enum {
    debug,
    info,
    warning,
    err,

    pub fn toString(self: LogLevel) []const u8 {
        return switch (self) {
            .debug => "DEBUG",
            .info => "INFO",
            .warning => "WARN",
            .err => "ERROR",
        };
    }

    pub fn color(self: LogLevel) []const u8 {
        return switch (self) {
            .debug => "\x1b[36m", // 青色
            .info => "\x1b[32m", // 绿色
            .warning => "\x1b[33m", // 黄色
            .err => "\x1b[31m", // 红色
        };
    }
};

/// 全局日志配置
pub var config = LogConfig{};

pub const LogConfig = struct {
    /// 最小日志级别
    min_level: LogLevel = .debug,
    /// 是否启用颜色
    use_color: bool = true,
    /// 是否显示时间戳
    show_timestamp: bool = true,
    /// 是否显示源文件位置
    show_source: bool = false,
};

/// 获取当前时间戳字符串
fn getTimestamp(buf: []u8) []const u8 {
    const timestamp = std.time.timestamp();
    const epoch_seconds: u64 = @intCast(timestamp);
    const epoch = std.time.epoch.EpochSeconds{ .secs = epoch_seconds };
    const day_seconds = epoch.getDaySeconds();
    const hours = day_seconds.getHoursIntoDay();
    const minutes = day_seconds.getMinutesIntoHour();
    const seconds = day_seconds.getSecondsIntoMinute();

    const len = std.fmt.bufPrint(buf, "{d:0>2}:{d:0>2}:{d:0>2}", .{ hours, minutes, seconds }) catch return "??:??:??";
    return buf[0..len.len];
}

/// 日志写入器
const LogWriter = struct {
    const Self = @This();

    pub fn log(
        comptime level: LogLevel,
        comptime src: std.builtin.SourceLocation,
        comptime format: []const u8,
        args: anytype,
    ) void {
        if (@intFromEnum(level) < @intFromEnum(config.min_level)) {
            return;
        }

        // 使用 std.debug.print 输出到 stderr
        var ts_buf: [16]u8 = undefined;

        // 时间戳
        if (config.show_timestamp) {
            const ts = getTimestamp(&ts_buf);
            std.debug.print("[{s}] ", .{ts});
        }

        // 日志级别
        if (config.use_color) {
            std.debug.print("{s}[{s}]\x1b[0m ", .{ level.color(), level.toString() });
        } else {
            std.debug.print("[{s}] ", .{level.toString()});
        }

        // 源文件位置
        if (config.show_source) {
            std.debug.print("{s}:{d}: ", .{ src.file, src.line });
        }

        // 消息内容
        std.debug.print(format ++ "\n", args);
    }
};

/// 调试日志
pub fn debug(comptime format: []const u8, args: anytype) void {
    LogWriter.log(.debug, @src(), format, args);
}

/// 信息日志
pub fn info(comptime format: []const u8, args: anytype) void {
    LogWriter.log(.info, @src(), format, args);
}

/// 警告日志
pub fn warn(comptime format: []const u8, args: anytype) void {
    LogWriter.log(.warning, @src(), format, args);
}

/// 错误日志
pub fn err(comptime format: []const u8, args: anytype) void {
    LogWriter.log(.err, @src(), format, args);
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
    info("  - 本地地址: {any}", .{local.local});
    if (local.remote) |r| {
        info("  - 外网地址: {any}", .{r});
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
    info("  - 本地地址: {any}", .{remote.local});
    if (remote.remote) |r| {
        info("  - 外网地址: {any}", .{r});
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
    info("远程端点: {any}", .{connection.remote_endpoint});
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
    info("本地地址: {any}", .{local_addr});
    if (public_addr) |addr| {
        info("公网地址: {any}", .{addr});
    } else {
        info("公网地址: (未检测到)", .{});
    }
    info("================================", .{});
}

/// 记录发送 TTL 包
pub fn logSendTtl(target: std.net.Address, ttl: u8) void {
    debug("发送 TTL 包 -> {any}, TTL={d}", .{ target, ttl });
}

/// 记录收到认证包
pub fn logRecvAuth(from: std.net.Address) void {
    debug("收到认证包 <- {any}", .{from});
}

/// 记录连接尝试
pub fn logConnectAttempt(target: std.net.Address, attempt: u32) void {
    debug("尝试连接 -> {any} (第 {d} 次)", .{ target, attempt });
}

test "log functions" {
    // 测试日志级别
    try std.testing.expectEqualStrings("DEBUG", LogLevel.debug.toString());
    try std.testing.expectEqualStrings("ERROR", LogLevel.err.toString());
}

test "timestamp generation" {
    var buf: [16]u8 = undefined;
    const ts = getTimestamp(&buf);
    // 时间戳格式应为 HH:MM:SS
    try std.testing.expect(ts.len == 8);
    try std.testing.expect(ts[2] == ':');
    try std.testing.expect(ts[5] == ':');
}
