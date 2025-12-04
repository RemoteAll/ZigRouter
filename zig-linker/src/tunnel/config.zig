//! 客户端配置文件模块
//! 支持 JSON 格式的配置文件，自动生成默认配置

const std = @import("std");
const types = @import("types.zig");
const log = @import("log.zig");

/// 传输方式配置项
pub const TransportConfig = struct {
    /// 传输方式名称
    name: []const u8,
    /// 是否启用
    enabled: bool = true,
    /// 优先级（数字越小越优先）
    priority: u8,
    /// 超时时间（秒）
    timeout_seconds: u16 = 10,
    /// 重试次数
    retry_count: u8 = 3,
};

/// 客户端配置
pub const ClientConfiguration = struct {
    /// 配置文件版本
    version: []const u8 = "1.0.0",

    /// 服务器地址
    server_addr: []const u8 = "127.0.0.1",
    /// 服务器端口
    server_port: u16 = 7891,

    /// 本机名称
    machine_name: []const u8 = "",
    /// 本机 ID（留空则自动生成）
    machine_id: []const u8 = "",

    /// 心跳间隔（秒）
    heartbeat_interval: u32 = 30,
    /// 连接超时（秒）
    connect_timeout: u32 = 10,
    /// 自动重连
    auto_reconnect: bool = true,
    /// 重连间隔（秒）
    reconnect_interval: u32 = 5,

    /// 是否自动检测 NAT 类型
    auto_detect_nat: bool = true,
    /// STUN 服务器地址
    stun_server: []const u8 = "stun.l.google.com",
    /// STUN 服务器端口
    stun_port: u16 = 19302,

    /// 端口映射端口（0 表示不使用）
    port_map_wan: u16 = 0,

    /// 日志级别: debug, info, warn, error
    log_level: []const u8 = "info",
    /// 是否启用彩色日志
    log_color: bool = true,

    /// 打洞方式配置（按优先级排序）
    transports: []TransportConfig = &.{},

    /// 获取默认的传输方式配置
    pub fn getDefaultTransports(allocator: std.mem.Allocator) ![]TransportConfig {
        var list: std.ArrayList(TransportConfig) = .{};
        errdefer list.deinit(allocator);

        // 按默认优先级排序的打洞方式
        try list.append(allocator, .{
            .name = "UdpPortMap",
            .enabled = true,
            .priority = 1,
            .timeout_seconds = 10,
            .retry_count = 3,
        });
        try list.append(allocator, .{
            .name = "TcpPortMap",
            .enabled = true,
            .priority = 2,
            .timeout_seconds = 10,
            .retry_count = 3,
        });
        try list.append(allocator, .{
            .name = "Udp",
            .enabled = true,
            .priority = 3,
            .timeout_seconds = 10,
            .retry_count = 3,
        });
        try list.append(allocator, .{
            .name = "UdpP2PNAT",
            .enabled = true,
            .priority = 4,
            .timeout_seconds = 15,
            .retry_count = 3,
        });
        try list.append(allocator, .{
            .name = "TcpP2PNAT",
            .enabled = true,
            .priority = 5,
            .timeout_seconds = 15,
            .retry_count = 3,
        });
        try list.append(allocator, .{
            .name = "TcpNutssb",
            .enabled = true,
            .priority = 6,
            .timeout_seconds = 15,
            .retry_count = 3,
        });
        try list.append(allocator, .{
            .name = "MsQuic",
            .enabled = false, // 默认禁用，需要特定平台支持
            .priority = 7,
            .timeout_seconds = 10,
            .retry_count = 2,
        });

        return list.toOwnedSlice(allocator);
    }

    /// 根据名称获取传输方式类型
    pub fn getTransportType(name: []const u8) ?types.TransportType {
        if (std.mem.eql(u8, name, "Udp")) return .udp;
        if (std.mem.eql(u8, name, "UdpP2PNAT")) return .udp_p2p_nat;
        if (std.mem.eql(u8, name, "TcpP2PNAT")) return .tcp_p2p_nat;
        if (std.mem.eql(u8, name, "TcpNutssb")) return .tcp_nutssb;
        if (std.mem.eql(u8, name, "UdpPortMap")) return .udp_port_map;
        if (std.mem.eql(u8, name, "TcpPortMap")) return .tcp_port_map;
        if (std.mem.eql(u8, name, "MsQuic")) return .msquic;
        return null;
    }

    /// 获取启用的传输方式列表（按优先级排序）
    pub fn getEnabledTransports(self: *const ClientConfiguration, allocator: std.mem.Allocator) ![]types.TransportType {
        var list: std.ArrayList(types.TransportType) = .{};
        errdefer list.deinit(allocator);

        // 创建临时数组用于排序
        var enabled: std.ArrayList(TransportConfig) = .{};
        defer enabled.deinit(allocator);

        for (self.transports) |t| {
            if (t.enabled) {
                try enabled.append(allocator, t);
            }
        }

        // 按优先级排序
        std.mem.sort(TransportConfig, enabled.items, {}, struct {
            fn lessThan(_: void, a: TransportConfig, b: TransportConfig) bool {
                return a.priority < b.priority;
            }
        }.lessThan);

        // 转换为 TransportType
        for (enabled.items) |t| {
            if (getTransportType(t.name)) |transport_type| {
                try list.append(allocator, transport_type);
            }
        }

        return list.toOwnedSlice(allocator);
    }

    /// 获取指定传输方式的配置
    pub fn getTransportConfig(self: *const ClientConfiguration, transport_type: types.TransportType) ?TransportConfig {
        const name = transport_type.name();
        for (self.transports) |t| {
            if (std.mem.eql(u8, t.name, name)) {
                return t;
            }
        }
        return null;
    }
};

/// 配置文件管理器
pub const ConfigManager = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    config: ClientConfiguration,
    config_path: []const u8,

    /// 初始化配置管理器
    pub fn init(allocator: std.mem.Allocator, config_path: []const u8) Self {
        return Self{
            .allocator = allocator,
            .config = ClientConfiguration{},
            .config_path = config_path,
        };
    }

    /// 释放资源
    pub fn deinit(self: *Self) void {
        if (self.config.transports.len > 0) {
            self.allocator.free(self.config.transports);
        }
    }

    /// 加载配置文件，如果不存在则创建默认配置
    pub fn load(self: *Self) !void {
        // 尝试打开配置文件
        const file = std.fs.cwd().openFile(self.config_path, .{}) catch |e| {
            if (e == error.FileNotFound) {
                log.info("配置文件不存在，正在创建默认配置: {s}", .{self.config_path});
                try self.createDefault();
                return;
            }
            return e;
        };
        defer file.close();

        // 读取文件内容
        const content = try file.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(content);

        // 解析 JSON
        try self.parseJson(content);

        log.info("配置文件加载成功: {s}", .{self.config_path});
        self.printConfig();
    }

    /// 创建默认配置文件
    pub fn createDefault(self: *Self) !void {
        // 设置默认传输方式
        self.config.transports = try ClientConfiguration.getDefaultTransports(self.allocator);

        // 保存到文件
        try self.save();

        log.info("默认配置文件已创建: {s}", .{self.config_path});
        self.printConfig();
    }

    /// 保存配置到文件
    pub fn save(self: *Self) !void {
        const file = try std.fs.cwd().createFile(self.config_path, .{});
        defer file.close();

        // 使用 ArrayList 构建 JSON 内容
        var content: std.ArrayList(u8) = .{};
        defer content.deinit(self.allocator);
        const writer = content.writer(self.allocator);

        // 手动生成格式化的 JSON
        try writer.writeAll("{\n");
        try writer.print("  \"version\": \"{s}\",\n", .{self.config.version});
        try writer.writeAll("\n");
        try writer.writeAll("  \"// 服务器配置\": \"\",\n");
        try writer.print("  \"server_addr\": \"{s}\",\n", .{self.config.server_addr});
        try writer.print("  \"server_port\": {d},\n", .{self.config.server_port});
        try writer.writeAll("\n");
        try writer.writeAll("  \"// 本机信息\": \"\",\n");
        try writer.print("  \"machine_name\": \"{s}\",\n", .{self.config.machine_name});
        try writer.print("  \"machine_id\": \"{s}\",\n", .{self.config.machine_id});
        try writer.writeAll("\n");
        try writer.writeAll("  \"// 连接设置\": \"\",\n");
        try writer.print("  \"heartbeat_interval\": {d},\n", .{self.config.heartbeat_interval});
        try writer.print("  \"connect_timeout\": {d},\n", .{self.config.connect_timeout});
        try writer.print("  \"auto_reconnect\": {s},\n", .{if (self.config.auto_reconnect) "true" else "false"});
        try writer.print("  \"reconnect_interval\": {d},\n", .{self.config.reconnect_interval});
        try writer.writeAll("\n");
        try writer.writeAll("  \"// NAT 检测设置\": \"\",\n");
        try writer.print("  \"auto_detect_nat\": {s},\n", .{if (self.config.auto_detect_nat) "true" else "false"});
        try writer.print("  \"stun_server\": \"{s}\",\n", .{self.config.stun_server});
        try writer.print("  \"stun_port\": {d},\n", .{self.config.stun_port});
        try writer.print("  \"port_map_wan\": {d},\n", .{self.config.port_map_wan});
        try writer.writeAll("\n");
        try writer.writeAll("  \"// 日志设置\": \"\",\n");
        try writer.print("  \"log_level\": \"{s}\",\n", .{self.config.log_level});
        try writer.print("  \"log_color\": {s},\n", .{if (self.config.log_color) "true" else "false"});
        try writer.writeAll("\n");
        try writer.writeAll("  \"// 打洞方式配置 (按优先级排序，数字越小越优先)\": \"\",\n");
        try writer.writeAll("  \"transports\": [\n");

        for (self.config.transports, 0..) |t, i| {
            try writer.writeAll("    {\n");
            try writer.print("      \"name\": \"{s}\",\n", .{t.name});
            try writer.print("      \"enabled\": {s},\n", .{if (t.enabled) "true" else "false"});
            try writer.print("      \"priority\": {d},\n", .{t.priority});
            try writer.print("      \"timeout_seconds\": {d},\n", .{t.timeout_seconds});
            try writer.print("      \"retry_count\": {d}\n", .{t.retry_count});
            if (i < self.config.transports.len - 1) {
                try writer.writeAll("    },\n");
            } else {
                try writer.writeAll("    }\n");
            }
        }

        try writer.writeAll("  ]\n");
        try writer.writeAll("}\n");

        // 一次性写入文件
        try file.writeAll(content.items);
    }

    /// 解析 JSON 配置
    fn parseJson(self: *Self, content: []const u8) !void {
        // 简单的 JSON 解析（不使用标准库的 JSON 解析器以避免复杂性）
        // 使用手动解析主要字段

        // 解析 server_addr
        if (findJsonString(content, "server_addr")) |value| {
            self.config.server_addr = try self.allocator.dupe(u8, value);
        }

        // 解析 server_port
        if (findJsonNumber(content, "server_port")) |value| {
            self.config.server_port = @intCast(value);
        }

        // 解析 machine_name
        if (findJsonString(content, "machine_name")) |value| {
            self.config.machine_name = try self.allocator.dupe(u8, value);
        }

        // 解析 machine_id
        if (findJsonString(content, "machine_id")) |value| {
            self.config.machine_id = try self.allocator.dupe(u8, value);
        }

        // 解析 heartbeat_interval
        if (findJsonNumber(content, "heartbeat_interval")) |value| {
            self.config.heartbeat_interval = @intCast(value);
        }

        // 解析 connect_timeout
        if (findJsonNumber(content, "connect_timeout")) |value| {
            self.config.connect_timeout = @intCast(value);
        }

        // 解析 auto_reconnect
        if (findJsonBool(content, "auto_reconnect")) |value| {
            self.config.auto_reconnect = value;
        }

        // 解析 reconnect_interval
        if (findJsonNumber(content, "reconnect_interval")) |value| {
            self.config.reconnect_interval = @intCast(value);
        }

        // 解析 auto_detect_nat
        if (findJsonBool(content, "auto_detect_nat")) |value| {
            self.config.auto_detect_nat = value;
        }

        // 解析 stun_server
        if (findJsonString(content, "stun_server")) |value| {
            self.config.stun_server = try self.allocator.dupe(u8, value);
        }

        // 解析 stun_port
        if (findJsonNumber(content, "stun_port")) |value| {
            self.config.stun_port = @intCast(value);
        }

        // 解析 port_map_wan
        if (findJsonNumber(content, "port_map_wan")) |value| {
            self.config.port_map_wan = @intCast(value);
        }

        // 解析 log_level
        if (findJsonString(content, "log_level")) |value| {
            self.config.log_level = try self.allocator.dupe(u8, value);
        }

        // 解析 log_color
        if (findJsonBool(content, "log_color")) |value| {
            self.config.log_color = value;
        }

        // 解析 transports 数组
        self.config.transports = try self.parseTransports(content);
    }

    /// 解析 transports 数组
    fn parseTransports(self: *Self, content: []const u8) ![]TransportConfig {
        var list: std.ArrayList(TransportConfig) = .{};
        errdefer list.deinit(self.allocator);

        // 查找 transports 数组
        const key = "\"transports\"";
        const key_pos = std.mem.indexOf(u8, content, key) orelse {
            // 如果没有找到，使用默认配置
            return ClientConfiguration.getDefaultTransports(self.allocator);
        };

        // 找到数组开始位置
        const array_start = std.mem.indexOfPos(u8, content, key_pos, "[") orelse return ClientConfiguration.getDefaultTransports(self.allocator);
        const array_end = findMatchingBracket(content, array_start) orelse return ClientConfiguration.getDefaultTransports(self.allocator);

        const array_content = content[array_start + 1 .. array_end];

        // 解析每个对象
        var pos: usize = 0;
        while (pos < array_content.len) {
            // 找到对象开始
            const obj_start = std.mem.indexOfPos(u8, array_content, pos, "{") orelse break;
            const obj_end = findMatchingBrace(array_content, obj_start) orelse break;

            const obj_content = array_content[obj_start .. obj_end + 1];

            // 解析对象字段
            var transport = TransportConfig{
                .name = "",
                .enabled = true,
                .priority = 255,
                .timeout_seconds = 10,
                .retry_count = 3,
            };

            if (findJsonString(obj_content, "name")) |name| {
                transport.name = try self.allocator.dupe(u8, name);
            }
            if (findJsonBool(obj_content, "enabled")) |enabled| {
                transport.enabled = enabled;
            }
            if (findJsonNumber(obj_content, "priority")) |priority| {
                transport.priority = @intCast(priority);
            }
            if (findJsonNumber(obj_content, "timeout_seconds")) |timeout| {
                transport.timeout_seconds = @intCast(timeout);
            }
            if (findJsonNumber(obj_content, "retry_count")) |retry| {
                transport.retry_count = @intCast(retry);
            }

            if (transport.name.len > 0) {
                try list.append(self.allocator, transport);
            }

            pos = obj_end + 1;
        }

        if (list.items.len == 0) {
            return ClientConfiguration.getDefaultTransports(self.allocator);
        }

        return list.toOwnedSlice(self.allocator);
    }

    /// 打印当前配置
    pub fn printConfig(self: *Self) void {
        log.info("========== 当前配置 ==========", .{});
        log.info("服务器: {s}:{d}", .{ self.config.server_addr, self.config.server_port });
        log.info("本机名称: {s}", .{if (self.config.machine_name.len > 0) self.config.machine_name else "(未设置)"});
        log.info("心跳间隔: {d}s", .{self.config.heartbeat_interval});
        log.info("自动重连: {s}", .{if (self.config.auto_reconnect) "是" else "否"});
        log.info("NAT检测: {s}", .{if (self.config.auto_detect_nat) "是" else "否"});
        log.info("日志级别: {s}", .{self.config.log_level});
        log.info("打洞方式 (按优先级排序):", .{});
        for (self.config.transports) |t| {
            const status = if (t.enabled) "✓" else "✗";
            log.info("  {s} [{d}] {s} (超时:{d}s, 重试:{d})", .{ status, t.priority, t.name, t.timeout_seconds, t.retry_count });
        }
        log.info("==============================", .{});
    }

    /// 应用日志配置
    pub fn applyLogConfig(self: *Self) void {
        // 设置日志级别
        if (std.mem.eql(u8, self.config.log_level, "debug")) {
            log.config.min_level = .debug;
        } else if (std.mem.eql(u8, self.config.log_level, "info")) {
            log.config.min_level = .info;
        } else if (std.mem.eql(u8, self.config.log_level, "warn")) {
            log.config.min_level = .warning;
        } else if (std.mem.eql(u8, self.config.log_level, "error")) {
            log.config.min_level = .err;
        }

        // 设置颜色
        log.config.use_color = self.config.log_color;
    }
};

// ============ JSON 解析辅助函数 ============

/// 查找 JSON 字符串值
fn findJsonString(content: []const u8, key: []const u8) ?[]const u8 {
    // 构造搜索模式 "key"
    var search_buf: [256]u8 = undefined;
    const search = std.fmt.bufPrint(&search_buf, "\"{s}\"", .{key}) catch return null;

    const key_pos = std.mem.indexOf(u8, content, search) orelse return null;

    // 找到冒号
    const colon_pos = std.mem.indexOfPos(u8, content, key_pos + search.len, ":") orelse return null;

    // 找到值的引号
    const quote_start = std.mem.indexOfPos(u8, content, colon_pos + 1, "\"") orelse return null;
    const quote_end = std.mem.indexOfPos(u8, content, quote_start + 1, "\"") orelse return null;

    return content[quote_start + 1 .. quote_end];
}

/// 查找 JSON 数字值
fn findJsonNumber(content: []const u8, key: []const u8) ?i64 {
    var search_buf: [256]u8 = undefined;
    const search = std.fmt.bufPrint(&search_buf, "\"{s}\"", .{key}) catch return null;

    const key_pos = std.mem.indexOf(u8, content, search) orelse return null;
    const colon_pos = std.mem.indexOfPos(u8, content, key_pos + search.len, ":") orelse return null;

    // 跳过空白
    var start = colon_pos + 1;
    while (start < content.len and (content[start] == ' ' or content[start] == '\t' or content[start] == '\n' or content[start] == '\r')) {
        start += 1;
    }

    // 找到数字结束位置
    var end = start;
    while (end < content.len and (content[end] >= '0' and content[end] <= '9')) {
        end += 1;
    }

    if (end > start) {
        return std.fmt.parseInt(i64, content[start..end], 10) catch return null;
    }

    return null;
}

/// 查找 JSON 布尔值
fn findJsonBool(content: []const u8, key: []const u8) ?bool {
    var search_buf: [256]u8 = undefined;
    const search = std.fmt.bufPrint(&search_buf, "\"{s}\"", .{key}) catch return null;

    const key_pos = std.mem.indexOf(u8, content, search) orelse return null;
    const colon_pos = std.mem.indexOfPos(u8, content, key_pos + search.len, ":") orelse return null;

    // 跳过空白
    var start = colon_pos + 1;
    while (start < content.len and (content[start] == ' ' or content[start] == '\t' or content[start] == '\n' or content[start] == '\r')) {
        start += 1;
    }

    if (start + 4 <= content.len and std.mem.eql(u8, content[start .. start + 4], "true")) {
        return true;
    }
    if (start + 5 <= content.len and std.mem.eql(u8, content[start .. start + 5], "false")) {
        return false;
    }

    return null;
}

/// 查找匹配的方括号
fn findMatchingBracket(content: []const u8, start: usize) ?usize {
    var depth: i32 = 0;
    var i = start;
    while (i < content.len) : (i += 1) {
        if (content[i] == '[') {
            depth += 1;
        } else if (content[i] == ']') {
            depth -= 1;
            if (depth == 0) {
                return i;
            }
        }
    }
    return null;
}

/// 查找匹配的花括号
fn findMatchingBrace(content: []const u8, start: usize) ?usize {
    var depth: i32 = 0;
    var i = start;
    while (i < content.len) : (i += 1) {
        if (content[i] == '{') {
            depth += 1;
        } else if (content[i] == '}') {
            depth -= 1;
            if (depth == 0) {
                return i;
            }
        }
    }
    return null;
}

// ============ 测试 ============

test "ConfigManager create default" {
    const allocator = std.testing.allocator;
    var manager = ConfigManager.init(allocator, "test_config.json");
    defer manager.deinit();

    // 使用默认传输配置
    manager.config.transports = try ClientConfiguration.getDefaultTransports(allocator);

    try std.testing.expect(manager.config.transports.len == 7);
    try std.testing.expectEqualStrings("UdpPortMap", manager.config.transports[0].name);
}

test "getTransportType" {
    try std.testing.expect(ClientConfiguration.getTransportType("Udp") == .udp);
    try std.testing.expect(ClientConfiguration.getTransportType("TcpP2PNAT") == .tcp_p2p_nat);
    try std.testing.expect(ClientConfiguration.getTransportType("Unknown") == null);
}
