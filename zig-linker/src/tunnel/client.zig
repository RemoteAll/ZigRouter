//! 打洞客户端
//! 负责连接信令服务器并发起/响应打洞请求
//! 参考 C# linker 项目的实现

const std = @import("std");
const net = std.net;
const posix = std.posix;
const zzig = @import("zzig");
const types = @import("types.zig");
const log = @import("log.zig");
const net_utils = @import("net_utils.zig");
const protocol = @import("protocol.zig");
const transport_mod = @import("transport.zig");
const config_mod = @import("config.zig");
const tls = @import("tls.zig");
const stun = @import("stun.zig");

/// 格式化地址为可读字符串
fn formatAddress(addr: net.Address, buf: []u8) []const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const writer = fbs.writer();

    switch (addr.any.family) {
        posix.AF.INET => {
            const bytes = @as(*const [4]u8, @ptrCast(&addr.in.sa.addr));
            writer.print("{d}.{d}.{d}.{d}:{d}", .{
                bytes[0],
                bytes[1],
                bytes[2],
                bytes[3],
                std.mem.bigToNative(u16, addr.in.sa.port),
            }) catch return "(error)";
        },
        posix.AF.INET6 => {
            writer.print("[IPv6]:{d}", .{
                std.mem.bigToNative(u16, addr.in6.sa.port),
            }) catch return "(error)";
        },
        else => {
            return "(unknown)";
        },
    }
    return fbs.getWritten();
}

/// 解析端点字符串为地址 (格式: ip:port 或 net.Address{...})
fn parseEndpointString(endpoint_str: []const u8) ?net.Address {
    // 尝试解析简单格式 "ip:port"
    if (std.mem.lastIndexOfScalar(u8, endpoint_str, ':')) |colon_idx| {
        const ip_str = endpoint_str[0..colon_idx];
        const port_str = endpoint_str[colon_idx + 1 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch return null;
        return net.Address.parseIp(ip_str, port) catch return null;
    }
    return null;
}

const builtin = @import("builtin");

/// 从 net.Address 中提取 IP 地址字节（用于比较公网 IP 是否相同）
/// 支持 IPv4 和 IPv6 地址
fn getIpBytes(addr: net.Address) [16]u8 {
    var result: [16]u8 = [_]u8{0} ** 16;
    switch (addr.any.family) {
        posix.AF.INET => {
            const bytes: *const [4]u8 = @ptrCast(&addr.in.sa.addr);
            @memcpy(result[0..4], bytes);
        },
        posix.AF.INET6 => {
            @memcpy(&result, &addr.in6.sa.addr);
        },
        else => {},
    }
    return result;
}

/// 获取本地时区偏移量（秒）
/// 返回本地时间相对于 UTC 的偏移秒数（例如 UTC+8 返回 28800）
fn getLocalTimezoneOffset() i64 {
    if (builtin.os.tag == .windows) {
        // Windows: 使用 GetTimeZoneInformation API
        const LONG = i32;
        const WCHAR = u16;

        const SYSTEMTIME = extern struct {
            wYear: u16,
            wMonth: u16,
            wDayOfWeek: u16,
            wDay: u16,
            wHour: u16,
            wMinute: u16,
            wSecond: u16,
            wMilliseconds: u16,
        };

        const TIME_ZONE_INFORMATION = extern struct {
            Bias: LONG,
            StandardName: [32]WCHAR,
            StandardDate: SYSTEMTIME,
            StandardBias: LONG,
            DaylightName: [32]WCHAR,
            DaylightDate: SYSTEMTIME,
            DaylightBias: LONG,
        };

        const GetTimeZoneInformation = struct {
            extern "kernel32" fn GetTimeZoneInformation(lpTimeZoneInformation: *TIME_ZONE_INFORMATION) u32;
        }.GetTimeZoneInformation;

        var tzi: TIME_ZONE_INFORMATION = undefined;
        _ = GetTimeZoneInformation(&tzi);

        // Bias 是以分钟为单位的偏移，且是负值（例如 UTC+8 返回 -480）
        // 需要转换为秒并反转符号
        return -tzi.Bias * 60;
    } else {
        // Unix/Linux: 简化处理，默认使用 UTC+8（中国标准时间）
        // 实际项目中可以读取 TZ 环境变量或 /etc/timezone
        return 8 * 3600;
    }
}

/// 客户端配置
pub const ClientConfig = struct {
    /// 服务器地址
    server_addr: []const u8 = "127.0.0.1",
    /// 服务器端口
    server_port: u16 = 18021,
    /// 本机 ID
    machine_id: []const u8 = "",
    /// 本机名称
    machine_name: []const u8 = "",
    /// 心跳间隔 (秒)
    heartbeat_interval: u32 = 30,
    /// 端口映射端口 (0 表示不使用)
    port_map_wan: u16 = 0,
    /// 自动检测 NAT 类型
    auto_detect_nat: bool = true,
    /// 是否启用 TLS 加密
    tls_enabled: bool = true,
    /// 是否跳过服务器证书验证（用于自签名证书）
    tls_skip_verify: bool = false,
    /// 传输方式配置列表（打洞方式优先级）
    transports: []const config_mod.TransportConfig = &.{},
    /// STUN 服务器配置
    stun: config_mod.StunConfiguration = .{},
};

/// 打洞结果
pub const PunchResult = struct {
    /// 是否成功
    success: bool,
    /// 连接
    connection: ?transport_mod.ITunnelConnection = null,
    /// 错误信息
    error_message: []const u8 = "",
    /// 耗时 (毫秒)
    duration_ms: u64 = 0,
};

/// 在线节点信息
pub const PeerListItem = struct {
    machine_id: []const u8,
    machine_name: []const u8,
    nat_type: types.NatType,
};

/// 打洞客户端
pub const PunchClient = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    config: ClientConfig,

    /// 连接到服务器的 socket
    server_socket: ?posix.socket_t = null,

    /// TLS 连接
    tls_conn: ?tls.TlsConnection = null,

    /// 本机 NAT 类型
    local_nat_type: types.NatType = .unknown,

    /// 本机公网地址
    public_addr: ?net.Address = null,

    /// 本机本地地址（TCP 连接地址）
    local_addr: ?net.Address = null,

    /// UDP 打洞本地地址（用于 NAT 打洞）
    /// 这是通过 UDP 探测时获取的本地地址，端口与 NAT 映射对应
    udp_local_addr: ?net.Address = null,

    /// UDP 打洞 socket（保持 NAT 映射活跃）
    /// 注册时创建，打洞时复用，保证端口与公网映射一致
    udp_punch_socket: ?posix.socket_t = null,

    /// TCP 打洞本地地址（用于 TCP NAT 打洞）
    /// 这是通过 TCP 探测时获取的本地地址，端口与 NAT 映射对应
    tcp_local_addr: ?net.Address = null,

    /// TCP 打洞公网地址
    tcp_public_addr: ?net.Address = null,

    /// 是否已注册
    registered: bool = false,

    /// 分配的 ID
    assigned_id: []const u8 = "",

    /// 传输管理器
    transport_manager: transport_mod.TransportManager,

    /// 当前序列号
    sequence: u32 = 0,

    /// 打洞回调
    on_punch_request: ?*const fn (*Self, *const protocol.PunchBegin) void = null,

    /// 节点上线回调
    on_peer_online: ?*const fn (*Self, *const protocol.PeerOnline) void = null,

    /// 节点下线回调
    on_peer_offline: ?*const fn (*Self, *const protocol.PeerOffline) void = null,

    /// 远程端口响应回调
    /// 参数: (self, 源机器ID, 本地端点字符串, 公网端点字符串)
    on_wan_port_response: ?*const fn (*Self, []const u8, []const u8, []const u8) void = null,

    /// NAT 类型检测线程
    nat_detect_thread: ?std.Thread = null,

    /// 线程停止标志
    should_stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    /// NAT 类型检测完成回调
    on_nat_type_detected: ?*const fn (*Self, types.NatType) void = null,

    /// 已建立的隧道连接池 (machine_id -> connection)
    active_connections: std.StringHashMap(transport_mod.ITunnelConnection) = undefined,

    /// 连接池互斥锁
    connections_mutex: std.Thread.Mutex = .{},

    /// 待处理的打洞请求 (target_machine_id -> PendingPunchRequest)
    pending_punch_requests: std.StringHashMap(PendingPunchRequest) = undefined,

    /// 待处理请求互斥锁
    pending_mutex: std.Thread.Mutex = .{},

    /// 服务器时间偏移量（毫秒）
    /// server_time = local_time + server_time_offset
    /// 用于在多客户端之间同步时间，确保打洞时序一致
    server_time_offset: i64 = 0,

    /// 时间同步是否完成
    time_synced: bool = false,

    /// 待处理打洞请求信息
    pub const PendingPunchRequest = struct {
        /// 目标机器 ID（已分配内存，需要释放）
        target_id: []const u8,
        /// 传输方式
        transport: types.TransportType,
        /// 事务 ID
        transaction_id: [16]u8,
        /// 创建时间（毫秒）
        created_at: i64,
        /// 本地端点（发起请求时的端点）
        local_endpoint: ?net.Address,
        /// 公网端点（发起请求时的端点）
        public_endpoint: ?net.Address,
    };

    pub fn init(allocator: std.mem.Allocator, config: ClientConfig) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .transport_manager = transport_mod.TransportManager.init(allocator, .{}),
            .active_connections = std.StringHashMap(transport_mod.ITunnelConnection).init(allocator),
            .pending_punch_requests = std.StringHashMap(PendingPunchRequest).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        // 停止 NAT 检测线程
        self.should_stop.store(true, .seq_cst);
        if (self.nat_detect_thread) |thread| {
            thread.join();
            self.nat_detect_thread = null;
        }

        // 清理待处理的打洞请求
        self.clearPendingRequests();
        self.pending_punch_requests.deinit();

        // 关闭所有活跃连接
        self.closeAllConnections();
        self.active_connections.deinit();

        // 关闭 UDP 打洞 socket
        if (self.udp_punch_socket) |sock| {
            posix.close(sock);
            self.udp_punch_socket = null;
        }

        self.disconnect();
        self.transport_manager.deinit();
        if (self.assigned_id.len > 0) {
            self.allocator.free(self.assigned_id);
        }
    }

    /// 关闭所有活跃连接
    fn closeAllConnections(self: *Self) void {
        self.connections_mutex.lock();
        defer self.connections_mutex.unlock();

        var it = self.active_connections.iterator();
        while (it.next()) |entry| {
            var conn = entry.value_ptr;
            conn.close();
            // 释放 machine_id 字符串
            self.allocator.free(entry.key_ptr.*);
        }
        self.active_connections.clearRetainingCapacity();
        log.debug("已关闭所有活跃连接", .{});
    }

    /// 清理所有待处理的打洞请求
    fn clearPendingRequests(self: *Self) void {
        self.pending_mutex.lock();
        defer self.pending_mutex.unlock();

        var it = self.pending_punch_requests.iterator();
        while (it.next()) |entry| {
            // 释放 target_id 字符串
            self.allocator.free(entry.value_ptr.target_id);
            self.allocator.free(entry.key_ptr.*);
        }
        self.pending_punch_requests.clearRetainingCapacity();
        log.debug("已清理所有待处理的打洞请求", .{});
    }

    /// 清理超时的待处理请求
    fn cleanupExpiredPendingRequests(self: *Self) void {
        self.pending_mutex.lock();
        defer self.pending_mutex.unlock();

        const now = std.time.milliTimestamp();
        const timeout_ms: i64 = 10000; // 10秒超时

        var to_remove: [32][]const u8 = undefined;
        var remove_count: usize = 0;

        var it = self.pending_punch_requests.iterator();
        while (it.next()) |entry| {
            if (now - entry.value_ptr.created_at > timeout_ms) {
                if (remove_count < to_remove.len) {
                    to_remove[remove_count] = entry.key_ptr.*;
                    remove_count += 1;
                }
            }
        }

        for (to_remove[0..remove_count]) |key| {
            if (self.pending_punch_requests.fetchRemove(key)) |kv| {
                log.warn("待处理打洞请求超时: {s}", .{kv.value.target_id});
                self.allocator.free(kv.value.target_id);
                self.allocator.free(kv.key);
            }
        }
    }

    /// 获取校准后的时间（毫秒时间戳）
    /// 使用服务器时间偏移量校准本地时间，确保多客户端时间一致
    pub fn getSyncedTime(self: *Self) i64 {
        const local_time = std.time.milliTimestamp();
        return local_time + self.server_time_offset;
    }

    /// 检查时间是否已同步
    pub fn isTimeSynced(self: *Self) bool {
        return self.time_synced;
    }

    /// 同步时间：发送心跳并等待响应，获取服务器时间
    /// 返回时间偏移量（毫秒），正值表示服务器时间比本地快
    pub fn syncTime(self: *Self) !i64 {
        const sock = self.server_socket orelse return error.NotConnected;

        log.info("正在同步服务器时间...", .{});

        // 发送心跳请求
        const header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .heartbeat,
            .data_length = 0,
            .sequence = self.nextSequence(),
        };

        var buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try header.serialize(&buf);

        // 使用 TLS 或普通 socket 发送
        if (self.tls_conn) |*tc| {
            _ = try tc.send(&buf);
        } else {
            _ = try posix.send(sock, &buf, 0);
        }

        // 等待心跳响应
        var recv_buf: [256]u8 = undefined;
        const recv_len = if (self.tls_conn) |*tc| blk: {
            break :blk try tc.recv(&recv_buf);
        } else blk: {
            break :blk try posix.recv(sock, &recv_buf, 0);
        };

        if (recv_len < protocol.MessageHeader.SIZE) {
            return error.ProtocolError;
        }

        const resp_header = protocol.MessageHeader.parse(recv_buf[0..protocol.MessageHeader.SIZE]) catch return error.ProtocolError;

        if (resp_header.msg_type != .heartbeat_response) {
            log.warn("期望心跳响应，收到: {any}", .{resp_header.msg_type});
            return error.UnexpectedResponse;
        }

        // 解析服务器时间
        const hb_payload = recv_buf[protocol.MessageHeader.SIZE..recv_len];
        if (hb_payload.len < 8) {
            return error.InvalidPayload;
        }

        const server_time = std.mem.readInt(i64, hb_payload[0..8], .big);
        const local_time = std.time.milliTimestamp();
        const new_offset = server_time - local_time;

        // 获取本地时区偏移（秒），用于转换为本地时间显示
        const tz_offset_secs = getLocalTimezoneOffset();

        // 转换为可读的本地时区时间格式
        const local_timestamp_secs: i64 = @intCast(@divTrunc(local_time, 1000));
        const server_timestamp_secs: i64 = @intCast(@divTrunc(server_time, 1000));

        // 应用时区偏移
        const local_adjusted: u64 = @intCast(local_timestamp_secs + tz_offset_secs);
        const server_adjusted: u64 = @intCast(server_timestamp_secs + tz_offset_secs);

        const local_epoch = std.time.epoch.EpochSeconds{ .secs = local_adjusted };
        const server_epoch = std.time.epoch.EpochSeconds{ .secs = server_adjusted };
        const local_year_day = local_epoch.getEpochDay().calculateYearDay();
        const server_year_day = server_epoch.getEpochDay().calculateYearDay();
        const local_month_day = local_year_day.calculateMonthDay();
        const server_month_day = server_year_day.calculateMonthDay();
        const local_day_secs = local_epoch.getDaySeconds();
        const server_day_secs = server_epoch.getDaySeconds();

        // 打印时间对比信息（本地时区时间）
        log.info("时间同步完成 - 本地时间: {d}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}, 服务端时间: {d}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}, 偏差: {d}ms", .{
            local_year_day.year,
            local_month_day.month.numeric(),
            local_month_day.day_index + 1,
            local_day_secs.getHoursIntoDay(),
            local_day_secs.getMinutesIntoHour(),
            local_day_secs.getSecondsIntoMinute(),
            server_year_day.year,
            server_month_day.month.numeric(),
            server_month_day.day_index + 1,
            server_day_secs.getHoursIntoDay(),
            server_day_secs.getMinutesIntoHour(),
            server_day_secs.getSecondsIntoMinute(),
            new_offset,
        });

        // 更新时间同步状态
        self.server_time_offset = new_offset;
        self.time_synced = true;

        // 同步日志模块的时间偏移
        log.setServerTimeOffset(new_offset);

        return new_offset;
    }

    /// 关闭与指定节点的连接
    fn closeConnectionByMachineId(self: *Self, machine_id: []const u8) void {
        self.connections_mutex.lock();
        defer self.connections_mutex.unlock();

        if (self.active_connections.fetchRemove(machine_id)) |kv| {
            var conn = kv.value;
            conn.close();
            // 释放 machine_id 字符串
            self.allocator.free(kv.key);
            log.info("已关闭与 {s} 的连接", .{machine_id});
        }
    }

    /// 保存连接到连接池
    fn saveConnection(self: *Self, machine_id: []const u8, conn: transport_mod.ITunnelConnection) void {
        self.connections_mutex.lock();
        defer self.connections_mutex.unlock();

        // 如果已有连接，先关闭旧连接
        if (self.active_connections.fetchRemove(machine_id)) |kv| {
            var old_conn = kv.value;
            old_conn.close();
            self.allocator.free(kv.key);
            log.debug("关闭与 {s} 的旧连接", .{machine_id});
        }

        // 复制 machine_id 并存储
        const id_copy = self.allocator.dupe(u8, machine_id) catch {
            log.err("保存连接失败: 内存分配失败", .{});
            return;
        };
        self.active_connections.put(id_copy, conn) catch {
            self.allocator.free(id_copy);
            log.err("保存连接失败: HashMap 错误", .{});
            return;
        };
        log.debug("已保存与 {s} 的连接", .{machine_id});
    }

    /// 连接到信令服务器
    pub fn connect(self: *Self) !void {
        if (self.server_socket != null) {
            log.warn("已连接到服务器", .{});
            return;
        }

        log.info("========================================", .{});
        log.info("  打洞客户端启动中...", .{});
        log.info("========================================", .{});

        if (self.config.tls_enabled) {
            log.info("  TLS 加密: 已启用", .{});
        } else {
            log.warn("  TLS 加密: 已禁用 (不建议在公网使用)", .{});
        }

        // 第一步：快速获取公网地址（用于确定 UDP 打洞端口）
        // 这是同步操作，因为打洞需要知道端口
        if (self.config.auto_detect_nat) {
            self.getPublicAddressQuick();
        }

        // 连接服务器
        const server_addr = try net.Address.parseIp(self.config.server_addr, self.config.server_port);

        // 根据地址族创建 socket
        const family_value = server_addr.any.family;
        const sock = blk: {
            if (family_value == 2) {
                break :blk try posix.socket(posix.AF.INET, posix.SOCK.STREAM, posix.IPPROTO.TCP);
            } else if (family_value == 10 or family_value == 23) {
                break :blk try posix.socket(posix.AF.INET6, posix.SOCK.STREAM, posix.IPPROTO.TCP);
            } else {
                return error.UnsupportedAddressFamily;
            }
        };
        errdefer posix.close(sock);

        try posix.connect(sock, &server_addr.any, server_addr.getOsSockLen());

        self.server_socket = sock;

        // 如果启用 TLS，进行握手
        if (self.config.tls_enabled) {
            var conn = tls.TlsConnection.initClient(sock, .{
                .enabled = true,
                // skip_verify 取反为 verify_peer
                .verify_peer = !self.config.tls_skip_verify,
                .server_name = self.config.server_addr,
            });
            conn.handshake() catch |e| {
                log.err("TLS 握手失败: {any}", .{e});
                return e;
            };
            self.tls_conn = conn;
            log.info("TLS 握手成功，连接已加密", .{});
        }

        // 获取本地地址
        var local_sockaddr: posix.sockaddr = undefined;
        var local_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        try posix.getsockname(sock, &local_sockaddr, &local_len);
        self.local_addr = .{ .any = local_sockaddr };

        log.info("已连接到服务器: {s}:{d}", .{ self.config.server_addr, self.config.server_port });

        // 格式化本地地址
        if (self.local_addr) |addr| {
            var addr_buf: [64]u8 = undefined;
            const local_addr_str = formatAddress(addr, &addr_buf);
            log.info("本地地址: {s}", .{local_addr_str});
        }

        // 发送注册消息
        try self.register();

        // 第二步：异步启动 STUN NAT 类型检测（不阻塞主流程）
        log.debug("NAT检测配置: auto_detect_nat={}, stun.enabled={}", .{ self.config.auto_detect_nat, self.config.stun.enabled });
        if (self.config.auto_detect_nat and self.config.stun.enabled) {
            self.startAsyncNatDetection();
        }
    }

    /// 断开连接
    pub fn disconnect(self: *Self) void {
        // 停止异步 NAT 检测
        self.should_stop.store(true, .seq_cst);

        if (self.tls_conn) |*tc| {
            tc.close();
            self.tls_conn = null;
        } else if (self.server_socket) |sock| {
            posix.close(sock);
        }
        self.server_socket = null;
        self.registered = false;
    }

    /// 快速获取公网地址（同步，用于确定 UDP 打洞端口）
    fn getPublicAddressQuick(self: *Self) void {
        log.info("正在获取公网地址...", .{});

        // 通过 Linker 服务端 UDP 探测获取公网地址
        if (self.getExternalAddrFromLinker()) |result| {
            self.public_addr = result.public_addr;
            self.udp_local_addr = result.local_addr;
            var udp_addr_buf: [64]u8 = undefined;
            const udp_addr_str = formatAddress(result.local_addr, &udp_addr_buf);
            log.info("UDP 打洞本地端口: {s}", .{udp_addr_str});
            if (result.public_addr) |pub_addr| {
                var pub_addr_buf: [64]u8 = undefined;
                log.info("公网地址: {s}", .{formatAddress(pub_addr, &pub_addr_buf)});
            }
        } else |e| {
            log.warn("UDP 探测失败: {any}，将使用 TCP 地址", .{e});
            self.udp_local_addr = self.local_addr;
        }
    }

    /// 启动异步 NAT 类型检测
    fn startAsyncNatDetection(self: *Self) void {
        log.info("启动异步 NAT 类型检测...", .{});

        // 启动检测线程
        self.nat_detect_thread = std.Thread.spawn(.{}, asyncNatDetectWorker, .{self}) catch |e| {
            log.warn("启动 NAT 检测线程失败: {any}", .{e});
            return;
        };
    }

    /// 异步 NAT 检测工作线程
    fn asyncNatDetectWorker(self: *Self) void {
        // 检查停止标志
        if (self.should_stop.load(.seq_cst)) return;

        // 执行 STUN NAT 类型检测
        if (self.detectNatTypeWithStun()) |nat_type| {
            self.local_nat_type = nat_type;
            log.info("========= NAT 检测结果 (异步) =========", .{});
            log.info("NAT 类型: {s}", .{nat_type.description()});
            log.info("================================", .{});

            // 调用回调通知
            if (self.on_nat_type_detected) |callback| {
                callback(self, nat_type);
            }

            // 如果已注册，更新服务器上的 NAT 类型
            if (self.registered and !self.should_stop.load(.seq_cst)) {
                self.updateNatTypeToServer(nat_type) catch |e| {
                    log.warn("更新 NAT 类型到服务器失败: {any}", .{e});
                };
            }
        } else |e| {
            log.warn("STUN NAT 类型检测失败: {any}", .{e});
        }
    }

    /// 更新 NAT 类型到服务器
    fn updateNatTypeToServer(self: *Self, nat_type: types.NatType) !void {
        _ = nat_type;
        // TODO: 发送 NAT 类型更新消息到服务器
        // 当前服务端协议可能还不支持此功能，暂时只记录日志
        log.debug("NAT 类型已更新为: {s}", .{self.local_nat_type.description()});
    }

    /// 检测 NAT 类型（保留用于手动同步检测）
    /// 1. 首先通过 Linker 服务端获取公网地址（确定 UDP 打洞端口）
    /// 2. 然后使用外部 STUN 服务器做完整的 NAT 类型检测 (RFC 3489)
    fn detectNatType(self: *Self) !void {
        log.info("正在检测 NAT 类型...", .{});

        // 第一步：通过 Linker 服务端 UDP 探测获取公网地址
        // 这一步确定打洞时要使用的 UDP 端口
        if (self.getExternalAddrFromLinker()) |result| {
            self.public_addr = result.public_addr;
            // 保存 UDP 本地地址，用于后续打洞
            // 这是关键：打洞时必须使用这个端口，而不是 TCP 连接的端口
            self.udp_local_addr = result.local_addr;
            log.info("通过 Linker 服务端获取公网地址成功", .{});
            var udp_addr_buf: [64]u8 = undefined;
            const udp_addr_str = formatAddress(result.local_addr, &udp_addr_buf);
            log.info("UDP 打洞本地端口: {s}", .{udp_addr_str});
        } else |e| {
            log.warn("Linker UDP 探测失败: {any}，将使用外部 STUN 服务器", .{e});
            // UDP 探测失败时，使用 TCP 地址作为备选
            self.udp_local_addr = self.local_addr;
        }

        // 第二步：使用外部 STUN 服务器做完整的 NAT 类型检测
        if (self.config.stun.enabled) {
            if (self.detectNatTypeWithStun()) |nat_type| {
                self.local_nat_type = nat_type;
            } else |e| {
                log.warn("STUN NAT 类型检测失败: {any}，NAT 类型未知", .{e});
                self.local_nat_type = .unknown;
            }
        } else {
            // STUN 禁用
            log.info("STUN NAT 类型检测已禁用", .{});
            self.local_nat_type = .unknown;
        }

        // 输出检测结果
        log.logNatDetection(
            self.local_nat_type,
            self.udp_local_addr orelse self.local_addr orelse net.Address.initIp4(.{ 0, 0, 0, 0 }, 0),
            self.public_addr,
        );
    }

    /// 使用外部 STUN 服务器检测 NAT 类型 (RFC 3489 完整算法)
    fn detectNatTypeWithStun(self: *Self) !types.NatType {
        // 获取 UDP 本地端口用于 STUN 检测
        const local_port = if (self.udp_local_addr) |addr| addr.getPort() else 0;
        const local_addr = net.Address.initIp4(.{ 0, 0, 0, 0 }, local_port);

        // 遍历 STUN 服务器列表
        for (self.config.stun.servers) |server_str| {
            log.info("尝试 STUN 服务器: {s}", .{server_str});

            // 解析服务器地址（支持域名 DNS 解析）
            const server_addr = self.parseStunServer(server_str) orelse {
                log.debug("无法解析 STUN 服务器: {s}", .{server_str});
                continue;
            };

            // 创建 STUN 客户端
            var client = stun.StunClient.init(server_addr, local_addr, .{
                .recv_timeout_ms = self.config.stun.timeout_ms,
                .retry_count = self.config.stun.retry_count,
                .use_rfc5389 = false, // 使用 RFC 3489 进行 NAT 类型检测
            });
            defer client.deinit();

            // 执行 NAT 类型检测
            if (client.query()) |result| {
                // 检测成功
                if (result.nat_type != .unknown and result.nat_type != .unsupported_server) {
                    log.info("STUN NAT 类型检测成功", .{});

                    // 如果之前没有获取到公网地址，使用 STUN 结果
                    if (self.public_addr == null) {
                        self.public_addr = result.public_endpoint;
                    }

                    return result.nat_type;
                } else if (result.nat_type == .unsupported_server) {
                    log.debug("STUN 服务器不支持完整 NAT 检测，尝试下一个", .{});
                    continue;
                }
            } else |e| {
                log.debug("STUN 服务器 {s} 检测失败: {any}", .{ server_str, e });
                continue;
            }
        }

        return error.AllStunServersFailed;
    }

    /// 解析 STUN 服务器地址 (格式: host:port)
    /// 支持 IP 地址和域名（使用 std.net.getAddressList 进行 DNS 解析）
    fn parseStunServer(self: *Self, server_str: []const u8) ?net.Address {
        // 查找端口分隔符
        if (std.mem.lastIndexOfScalar(u8, server_str, ':')) |colon_idx| {
            const host = server_str[0..colon_idx];
            const port_str = server_str[colon_idx + 1 ..];
            const port = std.fmt.parseInt(u16, port_str, 10) catch return null;

            // 先尝试解析为 IP 地址（快速路径）
            if (net.Address.parseIp4(host, port)) |addr| {
                return addr;
            } else |_| {}

            // 使用 std.net.getAddressList 进行 DNS 解析
            log.debug("DNS 解析: {s}", .{host});
            const addr_list = net.getAddressList(self.allocator, host, port) catch |e| {
                log.debug("DNS 解析 {s} 失败: {any}", .{ host, e });
                return null;
            };
            defer addr_list.deinit();

            // 返回第一个地址
            if (addr_list.addrs.len > 0) {
                return addr_list.addrs[0];
            }
        }
        return null;
    }

    /// 刷新 UDP 端口
    /// 重新进行 UDP 探测以获取最新的公网映射端口
    /// 在打洞前调用，确保使用最新的端口信息
    pub fn refreshUdpPort(self: *Self) !void {
        log.debug("刷新 UDP 端口...", .{});

        const result = try self.getExternalAddrFromLinker();

        // 更新本地和公网地址
        self.udp_local_addr = result.local_addr;
        if (result.public_addr) |pa| {
            self.public_addr = pa;
        }

        var local_buf: [64]u8 = undefined;
        var public_buf: [64]u8 = undefined;
        log.info("UDP 端口刷新完成: 本地={s}, 公网={s}", .{
            formatAddress(result.local_addr, &local_buf),
            if (result.public_addr) |pa| formatAddress(pa, &public_buf) else "未知",
        });
    }

    /// 刷新 TCP 端口
    /// 重新进行 TCP 探测以获取最新的公网映射端口
    /// 在 TCP 打洞前调用，确保使用最新的端口信息
    /// 按照 C# Linker 的方式：探测完成后关闭 socket，打洞时复用端口
    pub fn refreshTcpPort(self: *Self) !void {
        log.debug("刷新 TCP 端口...", .{});

        const result = try self.getExternalAddrFromLinkerTcp();

        // 更新 TCP 本地和公网地址（socket 已在探测函数中关闭）
        self.tcp_local_addr = result.local_addr;
        self.tcp_public_addr = result.public_addr;

        var local_buf: [64]u8 = undefined;
        var public_buf: [64]u8 = undefined;
        log.info("TCP 端口刷新完成: 本地={s}, 公网={s}", .{
            formatAddress(result.local_addr, &local_buf),
            if (result.public_addr) |pa| formatAddress(pa, &public_buf) else "未知",
        });
    }

    /// 通过 Linker 服务端 UDP 获取公网地址
    /// 返回公网地址、本地 UDP 地址，并保存 UDP socket 用于打洞
    const LinkerExternalResult = struct {
        public_addr: ?net.Address,
        local_addr: net.Address, // UDP socket 的本地地址（包含正确的打洞端口）
    };

    fn getExternalAddrFromLinker(self: *Self) !LinkerExternalResult {
        log.debug("开始 UDP 探测，服务器: {s}:{d}", .{ self.config.server_addr, self.config.server_port });

        // 如果已有 UDP socket，先关闭它
        if (self.udp_punch_socket) |old_sock| {
            posix.close(old_sock);
            self.udp_punch_socket = null;
        }

        // 创建 UDP socket（启用端口复用）
        const local_bind = net.Address.initIp4(.{ 0, 0, 0, 0 }, 0);
        const udp_sock = try net_utils.createReuseUdpSocket(local_bind);
        errdefer posix.close(udp_sock);

        // 设置超时 - Windows 使用毫秒
        if (@import("builtin").os.tag == .windows) {
            const timeout_ms: i32 = 2000; // 2秒
            posix.setsockopt(udp_sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout_ms)) catch |e| {
                log.warn("设置 UDP 超时失败: {any}", .{e});
            };
        } else {
            const timeout = posix.timeval{
                .sec = 2,
                .usec = 0,
            };
            posix.setsockopt(udp_sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch |e| {
                log.warn("设置 UDP 超时失败: {any}", .{e});
            };
        }

        // 服务器地址
        const server_addr = try net.Address.parseIp4(self.config.server_addr, self.config.server_port);
        var server_addr_buf: [64]u8 = undefined;
        log.debug("UDP 探测目标: {s}", .{formatAddress(server_addr, &server_addr_buf)});

        // 构建探测请求：[0x00][序号][随机数据]
        var request: [64]u8 = undefined;
        request[0] = 0; // 消息类型：公网地址探测
        request[1] = 0; // 序号

        // 填充随机数据
        var rng = std.Random.DefaultPrng.init(@bitCast(std.time.timestamp()));
        const random = rng.random();
        for (2..request.len) |i| {
            request[i] = random.int(u8);
        }

        // 多次重试发送请求
        var retry: u32 = 0;
        while (retry < 3) : (retry += 1) {
            log.debug("UDP 探测发送请求 ({d}/3)...", .{retry + 1});
            _ = posix.sendto(udp_sock, &request, 0, &server_addr.any, server_addr.getOsSockLen()) catch |e| {
                log.warn("UDP 探测发送失败: {any}", .{e});
                continue;
            };

            // 接收响应
            var response: [128]u8 = undefined;
            var src_addr: posix.sockaddr = undefined;
            var src_len: posix.socklen_t = @sizeOf(posix.sockaddr);

            const recv_len = posix.recvfrom(udp_sock, &response, 0, &src_addr, &src_len) catch |e| {
                if (e == error.WouldBlock or e == error.ConnectionTimedOut) {
                    log.debug("UDP 探测等待响应超时，重试...", .{});
                    continue;
                }
                log.warn("UDP 探测接收失败: {any}", .{e});
                continue;
            };

            if (recv_len < 7) {
                log.warn("UDP 探测响应长度不足: {d}", .{recv_len});
                continue;
            }

            log.debug("UDP 探测收到响应，长度: {d}", .{recv_len});

            // 解析响应（数据已与 0xFF 异或）
            for (0..recv_len) |i| {
                response[i] = response[i] ^ 0xFF;
            }

            // 解析地址族
            const family: u16 = response[0];
            var public_addr: net.Address = undefined;

            if (family == posix.AF.INET) {
                // IPv4: [family(1)][ip(4)][port(2)]
                const ip_bytes = response[1..5];
                const port_bytes = response[5..7];
                const port = (@as(u16, port_bytes[0]) << 8) | @as(u16, port_bytes[1]);

                public_addr = net.Address.initIp4(ip_bytes[0..4].*, port);
            } else if (family == posix.AF.INET6) {
                // IPv6: [family(1)][ip(16)][port(2)]
                if (recv_len < 19) {
                    log.warn("IPv6 响应长度不足", .{});
                    continue;
                }
                const port_bytes = response[17..19];
                const port = (@as(u16, port_bytes[0]) << 8) | @as(u16, port_bytes[1]);

                public_addr = net.Address.initIp6(response[1..17].*, port, 0, 0);
            } else {
                log.warn("不支持的地址族: {d}", .{family});
                continue;
            }

            // 获取 UDP socket 的本地地址（包含系统分配的端口）
            var local_sockaddr: posix.sockaddr = undefined;
            var local_len: posix.socklen_t = @sizeOf(posix.sockaddr);
            try posix.getsockname(udp_sock, &local_sockaddr, &local_len);
            var local_udp_addr = net.Address{ .any = local_sockaddr };

            // 关键修复：getsockname 返回的 IP 是 0.0.0.0（因为绑定的是通配符地址）
            // 需要获取实际的本机出口 IP，并结合 UDP 端口
            if (net_utils.getLocalOutboundAddress()) |outbound_addr| {
                const udp_port = local_udp_addr.getPort();
                local_udp_addr = net.Address.initIp4(
                    @as(*const [4]u8, @ptrCast(&outbound_addr.in.sa.addr)).*,
                    udp_port,
                );
            }

            var local_addr_buf: [64]u8 = undefined;
            var public_addr_buf: [64]u8 = undefined;
            log.info("UDP 探测成功! 本地: {s}, 公网: {s}", .{
                formatAddress(local_udp_addr, &local_addr_buf),
                formatAddress(public_addr, &public_addr_buf),
            });

            // 保存 UDP socket 用于后续打洞（不要关闭！）
            self.udp_punch_socket = udp_sock;

            return LinkerExternalResult{
                .public_addr = public_addr,
                .local_addr = local_udp_addr,
            };
        }

        // 所有重试都失败，关闭 socket
        posix.close(udp_sock);
        log.warn("UDP 探测失败：服务端可能未开启 UDP 端口 {d}", .{self.config.server_port});
        return error.ConnectionTimedOut;
    }

    /// TCP 端口探测结果
    const TcpExternalResult = struct {
        public_addr: ?net.Address,
        local_addr: net.Address, // TCP socket 的本地地址（包含正确的打洞端口）
        // socket 已关闭，打洞时使用 SO_REUSEADDR 复用端口
    };

    /// 通过 TCP 连接到 Linker 服务端获取公网地址
    /// 与 UDP 探测类似，但使用 TCP 协议，适用于 TCP 打洞场景
    /// 返回的 socket 需要在打洞时复用（使用相同的本地端口）
    fn getExternalAddrFromLinkerTcp(self: *Self) !TcpExternalResult {
        log.info("开始 TCP 端口探测，服务器: {s}:{d}", .{ self.config.server_addr, self.config.server_port });

        // 创建 TCP socket（启用端口复用）
        const sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM, posix.IPPROTO.TCP) catch |e| {
            log.err("创建 TCP socket 失败: {any}", .{e});
            return error.SocketCreateFailed;
        };
        errdefer posix.close(sock);

        // 设置端口复用
        net_utils.setReuseAddr(sock, true) catch {};
        net_utils.setReusePort(sock, true) catch {};

        // 绑定到任意端口（系统分配）
        const local_bind = net.Address.initIp4(.{ 0, 0, 0, 0 }, 0);
        posix.bind(sock, &local_bind.any, local_bind.getOsSockLen()) catch |e| {
            log.err("TCP bind 失败: {any}", .{e});
            return error.BindFailed;
        };

        // 服务器地址
        const server_addr = try net.Address.parseIp4(self.config.server_addr, self.config.server_port);

        // 连接到服务器
        posix.connect(sock, &server_addr.any, server_addr.getOsSockLen()) catch |e| {
            log.err("TCP 连接服务器失败: {any}", .{e});
            return error.ConnectFailed;
        };

        // 设置接收超时
        if (@import("builtin").os.tag == .windows) {
            const timeout_ms: i32 = 5000;
            posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout_ms)) catch {};
        } else {
            const timeout = posix.timeval{ .sec = 5, .usec = 0 };
            posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};
        }

        // 构建探测请求：[0x00][序号][随机数据]
        var request: [64]u8 = undefined;
        request[0] = 0; // 消息类型：端口探测
        request[1] = 0; // 序号

        // 填充随机数据
        var rng = std.Random.DefaultPrng.init(@bitCast(std.time.timestamp()));
        const random = rng.random();
        for (2..request.len) |i| {
            request[i] = random.int(u8);
        }

        // 发送请求
        _ = posix.send(sock, &request, 0) catch |e| {
            log.err("TCP 端口探测发送失败: {any}", .{e});
            return error.SendFailed;
        };

        // 接收响应
        var response: [128]u8 = undefined;
        const recv_len = posix.recv(sock, &response, 0) catch |e| {
            log.err("TCP 端口探测接收失败: {any}", .{e});
            return error.RecvFailed;
        };

        if (recv_len < 7) {
            log.warn("TCP 端口探测响应长度不足: {d}", .{recv_len});
            return error.InvalidResponse;
        }

        // 解析响应（数据已与 0xFF 异或）
        for (0..recv_len) |i| {
            response[i] = response[i] ^ 0xFF;
        }

        // 解析地址族
        const family: u16 = response[0];
        var public_addr: net.Address = undefined;

        if (family == posix.AF.INET) {
            // IPv4: [family(1)][ip(4)][port(2)]
            const ip_bytes = response[1..5];
            const port_bytes = response[5..7];
            const port = (@as(u16, port_bytes[0]) << 8) | @as(u16, port_bytes[1]);
            public_addr = net.Address.initIp4(ip_bytes[0..4].*, port);
        } else if (family == posix.AF.INET6) {
            // IPv6: [family(1)][ip(16)][port(2)]
            if (recv_len < 19) {
                log.warn("IPv6 响应长度不足", .{});
                return error.InvalidResponse;
            }
            const port_bytes = response[17..19];
            const port = (@as(u16, port_bytes[0]) << 8) | @as(u16, port_bytes[1]);
            public_addr = net.Address.initIp6(response[1..17].*, port, 0, 0);
        } else {
            log.warn("不支持的地址族: {d}", .{family});
            return error.InvalidResponse;
        }

        // 获取本地地址（包含系统分配的端口）
        var local_sockaddr: posix.sockaddr = undefined;
        var local_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        try posix.getsockname(sock, &local_sockaddr, &local_len);
        var local_tcp_addr = net.Address{ .any = local_sockaddr };

        // 获取实际的本机出口 IP
        if (net_utils.getLocalOutboundAddress()) |outbound_addr| {
            const tcp_port = local_tcp_addr.getPort();
            local_tcp_addr = net.Address.initIp4(
                @as(*const [4]u8, @ptrCast(&outbound_addr.in.sa.addr)).*,
                tcp_port,
            );
        }

        var local_addr_buf: [64]u8 = undefined;
        var public_addr_buf: [64]u8 = undefined;
        log.info("TCP 端口探测成功! 本地: {s}, 公网: {s}", .{
            formatAddress(local_tcp_addr, &local_addr_buf),
            formatAddress(public_addr, &public_addr_buf),
        });

        // 按照 C# Linker 的方式：关闭探测 socket，之后打洞时用 SO_REUSEADDR 复用端口
        // TCP 打洞原理：NAT 会记录 (本地端口 -> 公网端口) 的映射
        // 只要在映射超时前用相同端口发起新连接，NAT 可能会复用相同的公网端口
        posix.close(sock);
        log.info("TCP 探测 socket 已关闭，打洞时将复用端口 {d}", .{local_tcp_addr.getPort()});

        return TcpExternalResult{
            .public_addr = public_addr,
            .local_addr = local_tcp_addr,
        };
    }

    /// 注册到服务器
    fn register(self: *Self) !void {
        const sock = self.server_socket orelse return error.NotConnected;

        // 构造注册消息
        // 关键：local_endpoint 必须使用 UDP 探测时的本地地址，因为打洞时需要使用相同的端口
        // 否则当两个客户端在同一台机器上时，它们会使用 TCP 端口进行 UDP 打洞，导致失败
        const peer_info = protocol.PeerInfo{
            .machine_id = if (self.config.machine_id.len > 0) self.config.machine_id else self.generateMachineId(),
            .machine_name = if (self.config.machine_name.len > 0) self.config.machine_name else "zig-client",
            .nat_type = self.local_nat_type,
            // 使用 UDP 本地地址进行注册，这样服务器会告诉对方正确的打洞端口
            .local_endpoint = self.udp_local_addr orelse self.local_addr orelse net.Address.initIp4(.{ 0, 0, 0, 0 }, 0),
            .public_endpoint = null,
            .supported_transports = &[_]types.TransportType{},
            .port_map_wan = self.config.port_map_wan,
            .port_map_lan = 0,
            .route_level = 8,
        };

        const payload = try peer_info.serialize(self.allocator);
        defer self.allocator.free(payload);

        const header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .register,
            .data_length = @intCast(payload.len),
            .sequence = self.nextSequence(),
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try header.serialize(&header_buf);

        // 合并 header 和 payload 为一次发送
        var send_buf: [4096]u8 = undefined;
        @memcpy(send_buf[0..protocol.MessageHeader.SIZE], &header_buf);
        @memcpy(send_buf[protocol.MessageHeader.SIZE .. protocol.MessageHeader.SIZE + payload.len], payload);
        const total_len = protocol.MessageHeader.SIZE + payload.len;

        // 发送数据（使用 TLS 或普通 socket）
        if (self.tls_conn) |*tc| {
            _ = try tc.send(send_buf[0..total_len]);
        } else {
            _ = try posix.send(sock, send_buf[0..total_len], 0);
        }

        // 等待响应
        var recv_buf: [256]u8 = undefined;
        const recv_len = if (self.tls_conn) |*tc| blk: {
            break :blk try tc.recv(&recv_buf);
        } else blk: {
            break :blk try posix.recv(sock, &recv_buf, 0);
        };

        if (recv_len < protocol.MessageHeader.SIZE) {
            return error.ProtocolError;
        }

        const resp_header = protocol.MessageHeader.parse(recv_buf[0..protocol.MessageHeader.SIZE]) catch return error.ProtocolError;

        if (resp_header.msg_type != .register_response) {
            return error.ProtocolError;
        }

        const resp_payload = recv_buf[protocol.MessageHeader.SIZE..recv_len];
        if (resp_payload.len < 1) return error.ProtocolError;

        const success = resp_payload[0] == 1;
        if (!success) {
            log.err("注册失败", .{});
            return error.RegistrationFailed;
        }

        // 读取分配的 ID
        if (resp_payload.len >= 3) {
            const id_len = std.mem.readInt(u16, resp_payload[1..3], .big);
            if (resp_payload.len >= 3 + id_len) {
                self.assigned_id = try self.allocator.dupe(u8, resp_payload[3 .. 3 + id_len]);
            }
        }

        self.registered = true;

        log.info("========================================", .{});
        log.info("  注册成功!", .{});
        if (self.config.tls_enabled) {
            log.info("  连接状态: TLS 加密", .{});
        }
        log.info("  分配 ID: {s}", .{self.assigned_id});
        log.info("  NAT 类型: {s}", .{self.local_nat_type.description()});
        if (self.public_addr) |pub_addr| {
            const addr_str = log.formatAddress(pub_addr);
            log.info("  公网地址: {s}", .{std.mem.sliceTo(&addr_str, 0)});
        }
        log.info("========================================", .{});
    }

    /// 生成机器 ID
    fn generateMachineId(self: *Self) []const u8 {
        _ = self;
        // 简单生成一个基于时间戳的 ID
        const timestamp = std.time.timestamp();
        var buf: [32]u8 = undefined;
        const id = std.fmt.bufPrint(&buf, "zig-{d}", .{timestamp}) catch "zig-client";
        return id;
    }

    /// 获取下一个序列号
    fn nextSequence(self: *Self) u32 {
        self.sequence +%= 1;
        return self.sequence;
    }

    /// 获取在线节点列表
    pub fn listPeers(self: *Self, allocator: std.mem.Allocator) !std.ArrayList(PeerListItem) {
        const sock = self.server_socket orelse return error.NotConnected;
        if (!self.registered) return error.NotRegistered;

        // 发送列表请求
        const header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .register,
            .data_length = 0,
            .sequence = self.nextSequence(),
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try header.serialize(&header_buf);
        _ = try posix.send(sock, &header_buf, 0);

        // 接收响应
        var recv_buf: [4096]u8 = undefined;
        const recv_len = try posix.recv(sock, &recv_buf, 0);

        if (recv_len < protocol.MessageHeader.SIZE) {
            return error.ProtocolError;
        }

        const resp_header = protocol.MessageHeader.parse(recv_buf[0..protocol.MessageHeader.SIZE]) catch return error.ProtocolError;

        if (resp_header.msg_type != .list_peers_response) {
            return error.ProtocolError;
        }

        // 解析节点列表
        const list_payload = recv_buf[protocol.MessageHeader.SIZE..recv_len];
        if (list_payload.len < 2) return error.ProtocolError;

        const count = std.mem.readInt(u16, list_payload[0..2], .big);

        var list: std.ArrayList(PeerListItem) = .{};
        var offset: usize = 2;

        var i: u16 = 0;
        while (i < count) : (i += 1) {
            if (offset + 2 > list_payload.len) break;

            const id_len = std.mem.readInt(u16, list_payload[offset..][0..2], .big);
            offset += 2;

            if (offset + id_len > list_payload.len) break;
            const machine_id = try allocator.dupe(u8, list_payload[offset .. offset + id_len]);
            offset += id_len;

            if (offset + 2 > list_payload.len) break;
            const name_len = std.mem.readInt(u16, list_payload[offset..][0..2], .big);
            offset += 2;

            if (offset + name_len > list_payload.len) break;
            const machine_name = try allocator.dupe(u8, list_payload[offset .. offset + name_len]);
            offset += name_len;

            if (offset + 1 > list_payload.len) break;
            const nat_type: types.NatType = @enumFromInt(list_payload[offset]);
            offset += 1;

            try list.append(allocator, PeerListItem{
                .machine_id = machine_id,
                .machine_name = machine_name,
                .nat_type = nat_type,
            });
        }

        return list;
    }

    /// 请求打洞
    pub fn requestPunch(self: *Self, target_id: []const u8, transport_type: types.TransportType) !PunchResult {
        const sock = self.server_socket orelse return PunchResult{ .success = false, .error_message = "未连接到服务器" };
        if (!self.registered) return PunchResult{ .success = false, .error_message = "未注册" };

        const start_time = std.time.milliTimestamp();

        log.info("========================================", .{});
        log.info("  发起打洞请求", .{});
        log.info("  目标: {s}", .{target_id});
        log.info("  传输方式: {s}", .{transport_type.description()});
        log.info("========================================", .{});

        // 生成事务 ID 和流程 ID
        var transaction_id: [16]u8 = undefined;
        std.crypto.random.bytes(&transaction_id);
        const flow_id: u32 = @truncate(@as(u64, @intCast(std.time.timestamp())));

        // 发送打洞请求
        const request = protocol.PunchRequest{
            .flow_id = flow_id,
            .target_machine_id = target_id,
            .transport = transport_type,
            .direction = .forward,
            .transaction_id = transaction_id,
            .ssl = false,
        };

        const payload = try request.serialize(self.allocator);
        defer self.allocator.free(payload);
        const payload_len = payload.len;

        const header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .punch_request,
            .data_length = @intCast(payload_len),
            .sequence = self.nextSequence(),
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try header.serialize(&header_buf);

        // 合并 header 和 payload 一起发送
        var send_buf: [1024]u8 = undefined;
        @memcpy(send_buf[0..protocol.MessageHeader.SIZE], &header_buf);
        @memcpy(send_buf[protocol.MessageHeader.SIZE .. protocol.MessageHeader.SIZE + payload_len], payload);
        const total_len = protocol.MessageHeader.SIZE + payload_len;

        // 使用 TLS 或普通 socket 发送
        if (self.tls_conn) |*tc| {
            _ = tc.send(send_buf[0..total_len]) catch {
                return PunchResult{
                    .success = false,
                    .error_message = "TLS发送失败",
                    .duration_ms = @intCast(std.time.milliTimestamp() - start_time),
                };
            };
        } else {
            _ = posix.send(sock, send_buf[0..total_len], 0) catch {
                return PunchResult{
                    .success = false,
                    .error_message = "发送失败",
                    .duration_ms = @intCast(std.time.milliTimestamp() - start_time),
                };
            };
        }

        // 等待打洞开始通知
        var recv_buf: [4096]u8 = undefined;
        const recv_len = if (self.tls_conn) |*tc| blk: {
            break :blk tc.recv(&recv_buf) catch {
                return PunchResult{
                    .success = false,
                    .error_message = "TLS接收响应失败",
                    .duration_ms = @intCast(std.time.milliTimestamp() - start_time),
                };
            };
        } else blk: {
            break :blk posix.recv(sock, &recv_buf, 0) catch {
                return PunchResult{
                    .success = false,
                    .error_message = "接收响应失败",
                    .duration_ms = @intCast(std.time.milliTimestamp() - start_time),
                };
            };
        };

        if (recv_len < protocol.MessageHeader.SIZE) {
            return PunchResult{ .success = false, .error_message = "响应消息过短" };
        }

        const resp_header = protocol.MessageHeader.parse(recv_buf[0..protocol.MessageHeader.SIZE]) catch {
            return PunchResult{ .success = false, .error_message = "解析响应头失败" };
        };

        if (resp_header.msg_type == .punch_response) {
            // 直接收到错误响应
            const resp_payload = recv_buf[protocol.MessageHeader.SIZE..recv_len];
            if (resp_payload.len >= 1 and resp_payload[0] == 0) {
                return PunchResult{ .success = false, .error_message = "服务器拒绝打洞请求" };
            }
        }

        if (resp_header.msg_type != .punch_begin) {
            return PunchResult{ .success = false, .error_message = "收到意外的消息类型" };
        }

        // 解析打洞开始通知
        const begin_payload = recv_buf[protocol.MessageHeader.SIZE..recv_len];
        const begin = protocol.PunchBegin.parse(begin_payload) orelse {
            return PunchResult{ .success = false, .error_message = "解析打洞开始通知失败" };
        };

        log.info("收到打洞开始通知", .{});
        log.info("  对方 ID: {s}", .{begin.source_machine_id});
        log.info("  对方 NAT: {s}", .{begin.source_nat_type.description()});
        log.info("  方向: {s}", .{begin.direction.description()});

        // 解析对方地址
        var remote_endpoints: [4]net.Address = undefined;
        var endpoint_count: usize = 0;

        var addr_offset = begin.getSize();
        while (addr_offset < begin_payload.len and endpoint_count < 4) {
            const addr_type = begin_payload[addr_offset];
            addr_offset += 1;

            if (addr_type == 4 and addr_offset + 6 <= begin_payload.len) {
                // IPv4
                var addr: [4]u8 = undefined;
                @memcpy(&addr, begin_payload[addr_offset .. addr_offset + 4]);
                addr_offset += 4;

                var port_bytes: [2]u8 = undefined;
                @memcpy(&port_bytes, begin_payload[addr_offset .. addr_offset + 2]);
                const port = std.mem.readInt(u16, &port_bytes, .big);
                addr_offset += 2;

                remote_endpoints[endpoint_count] = net.Address.initIp4(addr, port);
                endpoint_count += 1;

                log.info("  对方端点 {d}: {any}", .{ endpoint_count, remote_endpoints[endpoint_count - 1] });
            } else if (addr_type == 6 and addr_offset + 18 <= begin_payload.len) {
                // IPv6
                var addr: [16]u8 = undefined;
                @memcpy(&addr, begin_payload[addr_offset .. addr_offset + 16]);
                addr_offset += 16;

                var port_bytes: [2]u8 = undefined;
                @memcpy(&port_bytes, begin_payload[addr_offset .. addr_offset + 2]);
                const port = std.mem.readInt(u16, &port_bytes, .big);
                addr_offset += 2;

                remote_endpoints[endpoint_count] = net.Address.initIp6(addr, port, 0, 0);
                endpoint_count += 1;

                log.info("  对方端点 {d}: {any}", .{ endpoint_count, remote_endpoints[endpoint_count - 1] });
            } else {
                break;
            }
        }

        if (endpoint_count == 0) {
            return PunchResult{ .success = false, .error_message = "没有可用的对方端点" };
        }

        // 解析对方的本地地址和公网地址
        // remote_endpoints[0] = 对方的本地地址
        // remote_endpoints[1] = 对方的公网地址
        const remote_local_addr = remote_endpoints[0];
        const remote_public_addr: ?net.Address = if (endpoint_count > 1) remote_endpoints[1] else null;

        // C# Linker 逻辑：只有当双方公网 IP 相同时（同一局域网），才尝试连接对方的本地地址
        // 参考 TunnelTransfer.cs 的 ParseRemoteEndPoint 方法
        var filtered_endpoints: [4]net.Address = undefined;
        var filtered_count: usize = 0;

        const my_public_addr = self.public_addr;
        const same_lan = if (my_public_addr != null and remote_public_addr != null) blk: {
            // 比较双方的公网 IP 地址（不比较端口）
            const my_ip = getIpBytes(my_public_addr.?);
            const remote_ip = getIpBytes(remote_public_addr.?);
            break :blk std.mem.eql(u8, &my_ip, &remote_ip);
        } else false;

        if (same_lan) {
            log.info("检测到双方在同一局域网（公网 IP 相同），将尝试连接本地地址", .{});
            // 同一局域网：先尝试本地地址，再尝试公网地址
            filtered_endpoints[filtered_count] = remote_local_addr;
            filtered_count += 1;
            if (remote_public_addr) |pub_addr| {
                filtered_endpoints[filtered_count] = pub_addr;
                filtered_count += 1;
            }
        } else {
            log.info("检测到双方在不同网络（公网 IP 不同），只尝试连接公网地址", .{});
            // 不同网络：只尝试公网地址
            if (remote_public_addr) |pub_addr| {
                filtered_endpoints[filtered_count] = pub_addr;
                filtered_count += 1;
            } else {
                // 如果没有公网地址，退回到本地地址（应该不会发生）
                log.warn("没有公网地址，退回到使用本地地址", .{});
                filtered_endpoints[filtered_count] = remote_local_addr;
                filtered_count += 1;
            }
        }

        // 打印过滤后的端点列表
        log.info("过滤后的目标端点数量: {d}", .{filtered_count});
        for (filtered_endpoints[0..filtered_count], 0..) |ep, i| {
            const ep_str = log.formatAddress(ep);
            log.info("  过滤后端点 [{d}]: {s}", .{ i, std.mem.sliceTo(&ep_str, 0) });
        }

        // 构造传输信息
        const transport_info = types.TunnelTransportInfo{
            .flow_id = begin.flow_id,
            .direction = begin.direction,
            .local = types.EndpointInfo{
                .machine_id = self.assigned_id,
                .machine_name = self.config.machine_name,
                .nat_type = self.local_nat_type,
                // 关键：使用 UDP 本地地址进行打洞，确保端口与 NAT 映射匹配
                .local = self.udp_local_addr orelse self.local_addr orelse net.Address.initIp4(.{ 0, 0, 0, 0 }, 0),
                .remote = self.public_addr,
                .port_map_wan = self.config.port_map_wan,
                .route_level = 8,
            },
            .remote = types.EndpointInfo{
                .machine_id = begin.source_machine_id,
                .machine_name = "",
                .nat_type = begin.source_nat_type,
                .local = remote_local_addr,
                .remote = remote_public_addr,
                .port_map_wan = 0,
                .route_level = 8,
            },
            .remote_endpoints = filtered_endpoints[0..filtered_count],
            .ssl = false,
        };

        // 执行打洞
        const connection = self.transport_manager.connect(transport_type, &transport_info) catch {
            return PunchResult{
                .success = false,
                .error_message = "打洞连接失败",
                .duration_ms = @intCast(std.time.milliTimestamp() - start_time),
                .connection = null,
            };
        };

        const duration = @as(u64, @intCast(std.time.milliTimestamp() - start_time));

        if (connection) |conn| {
            const remote_addr_str = log.formatAddress(conn.info.remote_endpoint);
            log.info("========================================", .{});
            log.info("  打洞成功!", .{});
            log.info("  耗时: {d} ms", .{duration});
            log.info("  远程端点: {s}", .{std.mem.sliceTo(&remote_addr_str, 0)});
            log.info("========================================", .{});

            return PunchResult{
                .success = true,
                .connection = conn,
                .duration_ms = duration,
            };
        } else {
            log.info("打洞失败，耗时: {d} ms", .{duration});
            return PunchResult{
                .success = false,
                .error_message = "打洞未成功建立连接",
                .duration_ms = duration,
            };
        }
    }

    /// 处理来自服务器的打洞开始通知
    /// 注意：此时不需要刷新端口，因为发起方已经获取了我们的最新端口
    /// 请求里的 local 端口就是我们之前返回给发起方的最新端口
    pub fn handlePunchBegin(self: *Self, begin: *const protocol.PunchBegin, remote_endpoints: []const net.Address) !PunchResult {
        const start_time = std.time.milliTimestamp();

        log.info("========================================", .{});
        log.info("  收到打洞请求", .{});
        log.info("  发起方: {s}", .{begin.source_machine_id});
        log.info("  发起方 NAT: {s}", .{begin.source_nat_type.description()});
        log.info("  传输方式: {s}", .{begin.transport.description()});
        log.info("  消息中本地端点: {s}", .{begin.remote_local_endpoint});
        log.info("  消息中公网端点: {s}", .{begin.remote_public_endpoint});
        log.info("========================================", .{});

        // 解析消息中携带的本地端口信息（这是发起方之前获取的我方最新端口）
        // 不要在这里刷新，否则会导致端口不匹配
        const parsed_local = net_utils.parseEndpointString(begin.my_local_endpoint);
        const parsed_public = net_utils.parseEndpointString(begin.my_public_endpoint);

        // 如果消息中有端点信息就用，否则回退到当前已知的端点
        const local_addr = parsed_local orelse self.udp_local_addr orelse self.local_addr orelse net.Address.initIp4(.{ 0, 0, 0, 0 }, 0);
        const public_addr = parsed_public orelse self.public_addr;

        var local_buf: [64]u8 = undefined;
        var public_buf: [64]u8 = undefined;
        log.info("使用端口: 本地 {s}, 公网 {s}", .{
            formatAddress(local_addr, &local_buf),
            if (public_addr) |pa| formatAddress(pa, &public_buf) else "未知",
        });

        // 解析对方的本地地址和公网地址
        const remote_local_addr = if (remote_endpoints.len > 0) remote_endpoints[0] else net.Address.initIp4(.{ 0, 0, 0, 0 }, 0);
        const remote_public_addr: ?net.Address = if (remote_endpoints.len > 1) remote_endpoints[1] else null;

        // C# Linker 逻辑：只有当双方公网 IP 相同时（同一局域网），才尝试连接对方的本地地址
        var filtered_endpoints: [4]net.Address = undefined;
        var filtered_count: usize = 0;

        const same_lan = if (public_addr != null and remote_public_addr != null) blk: {
            const my_ip = getIpBytes(public_addr.?);
            const remote_ip = getIpBytes(remote_public_addr.?);
            break :blk std.mem.eql(u8, &my_ip, &remote_ip);
        } else false;

        if (same_lan) {
            log.info("检测到双方在同一局域网（公网 IP 相同），将尝试连接本地地址", .{});
            filtered_endpoints[filtered_count] = remote_local_addr;
            filtered_count += 1;
            if (remote_public_addr) |pub_addr| {
                filtered_endpoints[filtered_count] = pub_addr;
                filtered_count += 1;
            }
        } else {
            log.info("检测到双方在不同网络（公网 IP 不同），只尝试连接公网地址", .{});
            if (remote_public_addr) |pub_addr| {
                filtered_endpoints[filtered_count] = pub_addr;
                filtered_count += 1;
            } else {
                log.warn("没有公网地址，退回到使用本地地址", .{});
                filtered_endpoints[filtered_count] = remote_local_addr;
                filtered_count += 1;
            }
        }

        // 打印过滤后的端点列表
        log.info("过滤后的目标端点数量: {d}", .{filtered_count});
        for (filtered_endpoints[0..filtered_count], 0..) |ep, i| {
            const ep_str = log.formatAddress(ep);
            log.info("  过滤后端点 [{d}]: {s}", .{ i, std.mem.sliceTo(&ep_str, 0) });
        }

        // 构造传输信息 (注意方向是反的)
        const transport_info = types.TunnelTransportInfo{
            .flow_id = begin.flow_id,
            .direction = if (begin.direction == .forward) .reverse else .forward,
            .local = types.EndpointInfo{
                .machine_id = self.assigned_id,
                .machine_name = self.config.machine_name,
                .nat_type = self.local_nat_type,
                // 使用消息中的端口，这是发起方获取的我方最新端口
                .local = local_addr,
                .public = public_addr,
                .port_map_wan = self.config.port_map_wan,
                .route_level = 8,
            },
            .remote = types.EndpointInfo{
                .machine_id = begin.source_machine_id,
                .machine_name = "",
                .nat_type = begin.source_nat_type,
                .local = remote_local_addr,
                .public = remote_public_addr,
                .port_map_wan = 0,
                .route_level = 8,
            },
            .remote_endpoints = filtered_endpoints[0..filtered_count],
            .ssl = false,
        };

        // 执行打洞
        const connection = self.transport_manager.connect(begin.transport, &transport_info) catch |e| {
            _ = e;
            return PunchResult{
                .success = false,
                .error_message = "打洞连接失败",
                .duration_ms = @intCast(std.time.milliTimestamp() - start_time),
                .connection = null,
            };
        };

        const duration = @as(u64, @intCast(std.time.milliTimestamp() - start_time));

        if (connection) |conn| {
            log.info("被动打洞成功! 耗时: {d} ms", .{duration});
            return PunchResult{
                .success = true,
                .connection = conn,
                .duration_ms = duration,
            };
        } else {
            return PunchResult{
                .success = false,
                .error_message = "被动打洞失败",
                .duration_ms = duration,
            };
        }
    }

    /// 发送心跳
    pub fn sendHeartbeat(self: *Self) !void {
        if (self.server_socket == null) return error.NotConnected;

        const header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .heartbeat,
            .data_length = 0,
            .sequence = self.nextSequence(),
        };

        var buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try header.serialize(&buf);

        // 使用 TLS 或普通 socket 发送
        if (self.tls_conn) |*tc| {
            _ = try tc.send(&buf);
        } else {
            _ = try posix.send(self.server_socket.?, &buf, 0);
        }
    }

    /// 发送打洞请求
    pub fn sendPunchRequest(self: *Self, target_machine_id: []const u8) !void {
        if (self.server_socket == null) return error.NotConnected;

        // 构建打洞请求 payload
        var payload_buf: [512]u8 = undefined;
        var payload_stream = std.io.fixedBufferStream(&payload_buf);
        const writer = payload_stream.writer();

        // 目标机器 ID (2 bytes length + data)
        try writer.writeInt(u16, @intCast(target_machine_id.len), .big);
        try writer.writeAll(target_machine_id);

        // 传输方式 (1 byte) - 使用 TCP P2P NAT
        try writer.writeByte(@intFromEnum(types.TransportType.tcp_p2p_nat));

        // 方向 (1 byte) - 正向
        try writer.writeByte(@intFromEnum(types.TunnelDirection.forward));

        // 事务 ID (16 bytes)
        const transaction_id = protocol.generateTransactionId();
        try writer.writeAll(&transaction_id);

        // 流 ID (4 bytes)
        try writer.writeInt(u32, 0, .big);

        // SSL (1 byte)
        try writer.writeByte(if (self.config.tls_enabled) 1 else 0);

        const payload = payload_stream.getWritten();

        const header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .punch_request,
            .data_length = @intCast(payload.len),
            .sequence = self.nextSequence(),
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try header.serialize(&header_buf);

        // 合并 header 和 payload
        var send_buf: [768]u8 = undefined;
        @memcpy(send_buf[0..protocol.MessageHeader.SIZE], &header_buf);
        @memcpy(send_buf[protocol.MessageHeader.SIZE .. protocol.MessageHeader.SIZE + payload.len], payload);
        const total_len = protocol.MessageHeader.SIZE + payload.len;

        // 使用 TLS 或普通 socket 发送
        if (self.tls_conn) |*tc| {
            _ = try tc.send(send_buf[0..total_len]);
        } else {
            _ = try posix.send(self.server_socket.?, send_buf[0..total_len], 0);
        }

        log.info("已发送打洞请求，目标: {s}", .{target_machine_id});
    }

    /// 发起打洞（异步流程）
    /// 1. 刷新本地端口
    /// 2. 发送获取远程端口请求
    /// 3. 等待远程端口响应后在消息循环中继续打洞
    pub fn initiatePunch(self: *Self, target_machine_id: []const u8, transport: types.TransportType) !void {
        if (self.server_socket == null) return error.NotConnected;

        log.info("", .{});
        log.info("╔══════════════════════════════════════════════════════════════╗", .{});
        log.info("║              发起打洞流程                                    ║", .{});
        log.info("╠══════════════════════════════════════════════════════════════╣", .{});
        log.info("║ 目标: {s}", .{target_machine_id});
        log.info("║ 传输方式: {s}", .{transport.description()});
        log.info("╚══════════════════════════════════════════════════════════════╝", .{});

        // 第一步：刷新本地 UDP 端口
        // 第一步：根据传输类型刷新本地端口
        var local_endpoint: ?net.Address = null;
        var public_endpoint: ?net.Address = null;

        if (transport.protocolType() == .tcp) {
            // TCP 传输：使用 TCP 端口探测
            log.info("步骤 1/3: 刷新本地 TCP 端口...", .{});
            self.refreshTcpPort() catch |e| {
                log.err("刷新 TCP 端口失败: {any}", .{e});
                log.err("TCP P2P NAT 打洞需要服务端支持 TCP 端口探测", .{});
                log.err("请确保服务端已更新到支持 TCP 端口探测的版本", .{});
                return error.TcpPortProbeFailed;
            };
            local_endpoint = self.tcp_local_addr;
            public_endpoint = self.tcp_public_addr;

            // 验证 TCP 端口探测结果
            if (local_endpoint == null or public_endpoint == null) {
                log.err("TCP 端口探测未返回有效地址", .{});
                return error.TcpPortProbeFailed;
            }
        } else {
            // UDP 传输：使用 UDP 端口探测
            log.info("步骤 1/3: 刷新本地 UDP 端口...", .{});
            self.refreshUdpPort() catch |e| {
                log.warn("刷新 UDP 端口失败: {any}，使用已有端口", .{e});
            };
            local_endpoint = self.udp_local_addr;
            public_endpoint = self.public_addr;
        }

        var local_buf: [64]u8 = undefined;
        var public_buf: [64]u8 = undefined;
        log.info("本地端口: {s}, 公网端口: {s}", .{
            if (local_endpoint) |le| formatAddress(le, &local_buf) else "未知",
            if (public_endpoint) |pe| formatAddress(pe, &public_buf) else "未知",
        });

        // 第二步：创建待处理请求记录
        log.info("步骤 2/3: 请求目标端口信息...", .{});

        const transaction_id = protocol.generateTransactionId();

        // 分配并保存 target_id
        const target_id_copy = try self.allocator.dupe(u8, target_machine_id);
        errdefer self.allocator.free(target_id_copy);

        const pending_request = PendingPunchRequest{
            .target_id = target_id_copy,
            .transport = transport,
            .transaction_id = transaction_id,
            .created_at = std.time.milliTimestamp(),
            .local_endpoint = local_endpoint,
            .public_endpoint = public_endpoint,
        };

        // 保存到待处理列表
        {
            self.pending_mutex.lock();
            defer self.pending_mutex.unlock();

            // 分配 key
            const key_copy = try self.allocator.dupe(u8, target_machine_id);
            errdefer self.allocator.free(key_copy);

            // 如果已有针对该目标的请求，先移除
            if (self.pending_punch_requests.fetchRemove(target_machine_id)) |old| {
                self.allocator.free(old.value.target_id);
                self.allocator.free(old.key);
            }

            try self.pending_punch_requests.put(key_copy, pending_request);
        }

        // 第三步：发送获取远程端口请求
        // 根据传输类型确定协议类型: 0=UDP, 1=TCP
        const protocol_type: u8 = if (transport.protocolType() == .tcp) 1 else 0;
        try self.sendGetWanPortRequest(target_machine_id, protocol_type);

        log.info("步骤 3/3: 等待目标端口响应...", .{});
        log.info("（响应后将在消息循环中自动继续打洞流程）", .{});
    }

    /// 发送获取远程端口请求
    /// 在打洞前调用，让目标刷新端口并返回最新端口信息
    /// protocol_type: 0=UDP, 1=TCP - 告诉对方用什么协议探测端口
    pub fn sendGetWanPortRequest(self: *Self, target_machine_id: []const u8, protocol_type: u8) !void {
        if (self.server_socket == null) return error.NotConnected;

        // 构建请求 payload: 目标机器 ID + 协议类型
        var payload_buf: [256]u8 = undefined;
        var payload_stream = std.io.fixedBufferStream(&payload_buf);
        const writer = payload_stream.writer();

        // 目标机器 ID (2 bytes length + data)
        try writer.writeInt(u16, @intCast(target_machine_id.len), .big);
        try writer.writeAll(target_machine_id);

        // 协议类型 (1 byte): 0=UDP, 1=TCP
        try writer.writeByte(protocol_type);

        const payload = payload_stream.getWritten();

        const header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .get_wan_port,
            .data_length = @intCast(payload.len),
            .sequence = self.nextSequence(),
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try header.serialize(&header_buf);

        // 合并 header 和 payload
        var send_buf: [512]u8 = undefined;
        @memcpy(send_buf[0..protocol.MessageHeader.SIZE], &header_buf);
        @memcpy(send_buf[protocol.MessageHeader.SIZE .. protocol.MessageHeader.SIZE + payload.len], payload);
        const total_len = protocol.MessageHeader.SIZE + payload.len;

        // 使用 TLS 或普通 socket 发送
        if (self.tls_conn) |*tc| {
            _ = try tc.send(send_buf[0..total_len]);
        } else {
            _ = try posix.send(self.server_socket.?, send_buf[0..total_len], 0);
        }

        log.debug("已发送获取远程端口请求，目标: {s}, 协议类型: {d}", .{ target_machine_id, protocol_type });
    }

    /// 发送获取端口响应（当被请求时调用）
    /// 刷新本地端口并返回最新端口信息
    /// protocol_type: 0=UDP, 1=TCP - 根据对方需要的协议类型刷新对应端口
    pub fn sendGetWanPortResponse(self: *Self, requester_id: []const u8, protocol_type: u8) !void {
        if (self.server_socket == null) return error.NotConnected;

        // 根据协议类型刷新对应端口
        var local_addr: ?net.Address = null;
        var public_addr: ?net.Address = null;

        if (protocol_type == 1) {
            // TCP 协议 - 刷新 TCP 端口
            self.refreshTcpPort() catch |e| {
                log.err("刷新 TCP 端口失败: {any}", .{e});
                log.err("无法响应 TCP 端口查询，服务端可能不支持 TCP 端口探测", .{});
                return error.TcpPortProbeFailed;
            };
            local_addr = self.tcp_local_addr;
            public_addr = self.tcp_public_addr;

            // 验证 TCP 端口探测结果
            if (local_addr == null or public_addr == null) {
                log.err("TCP 端口探测未返回有效地址", .{});
                return error.TcpPortProbeFailed;
            }

            var local_buf: [64]u8 = undefined;
            var public_buf: [64]u8 = undefined;
            log.info("使用 TCP 端口响应: 本地={s}, 公网={s}", .{
                if (local_addr) |la| formatAddress(la, &local_buf) else "未知",
                if (public_addr) |pa| formatAddress(pa, &public_buf) else "未知",
            });
        } else {
            // UDP 协议（默认） - 刷新 UDP 端口
            self.refreshUdpPort() catch |e| {
                log.warn("刷新 UDP 端口失败: {any}", .{e});
            };
            local_addr = self.udp_local_addr orelse self.local_addr;
            public_addr = self.public_addr;

            var local_buf: [64]u8 = undefined;
            var public_buf: [64]u8 = undefined;
            log.info("使用 UDP 端口响应: 本地={s}, 公网={s}", .{
                if (local_addr) |la| formatAddress(la, &local_buf) else "未知",
                if (public_addr) |pa| formatAddress(pa, &public_buf) else "未知",
            });
        }

        // 构建响应 payload
        var payload_buf: [512]u8 = undefined;
        var payload_stream = std.io.fixedBufferStream(&payload_buf);
        const writer = payload_stream.writer();

        // 请求者 ID (2 bytes length + data)
        try writer.writeInt(u16, @intCast(requester_id.len), .big);
        try writer.writeAll(requester_id);

        // 本地端点字符串 (2 bytes length + data)
        var local_str_buf: [64]u8 = undefined;
        const local_str = if (local_addr) |la| formatAddress(la, &local_str_buf) else "";
        try writer.writeInt(u16, @intCast(local_str.len), .big);
        if (local_str.len > 0) try writer.writeAll(local_str);

        // 公网端点字符串 (2 bytes length + data)
        var public_str_buf: [64]u8 = undefined;
        const public_str = if (public_addr) |pa| formatAddress(pa, &public_str_buf) else "";
        try writer.writeInt(u16, @intCast(public_str.len), .big);
        if (public_str.len > 0) try writer.writeAll(public_str);

        const payload = payload_stream.getWritten();

        const header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .get_wan_port_response,
            .data_length = @intCast(payload.len),
            .sequence = self.nextSequence(),
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try header.serialize(&header_buf);

        // 合并 header 和 payload
        var send_buf: [768]u8 = undefined;
        @memcpy(send_buf[0..protocol.MessageHeader.SIZE], &header_buf);
        @memcpy(send_buf[protocol.MessageHeader.SIZE .. protocol.MessageHeader.SIZE + payload.len], payload);
        const total_len = protocol.MessageHeader.SIZE + payload.len;

        // 使用 TLS 或普通 socket 发送
        if (self.tls_conn) |*tc| {
            _ = try tc.send(send_buf[0..total_len]);
        } else {
            _ = try posix.send(self.server_socket.?, send_buf[0..total_len], 0);
        }

        log.info("已发送端口响应给 {s}: 本地={s}, 公网={s}, 协议={s}", .{
            requester_id,
            local_str,
            public_str,
            if (protocol_type == 1) "TCP" else "UDP",
        });
    }

    /// 发送包含双方端口信息的打洞开始消息
    /// 这是发起方在收到目标端口响应后调用的
    /// 服务器会将此消息转发给目标，并交换 Local/Remote 字段
    fn sendPunchBeginWithPorts(
        self: *Self,
        target_id: []const u8,
        transport: types.TransportType,
        transaction_id: [16]u8,
        my_local: ?net.Address,
        my_public: ?net.Address,
        remote_local: ?net.Address,
        remote_public: ?net.Address,
    ) !void {
        if (self.server_socket == null) return error.NotConnected;

        // 构建打洞开始消息 payload
        // 格式：
        // - target_id: 2 bytes len + data
        // - source_nat_type: 1 byte
        // - transport: 1 byte
        // - direction: 1 byte (forward)
        // - transaction_id: 16 bytes
        // - flow_id: 4 bytes
        // - ssl: 1 byte
        // - same_lan: 1 byte
        // - my_public_endpoint: 2 bytes len + string
        // - my_local_endpoint: 2 bytes len + string
        // - remote_public_endpoint: 2 bytes len + string
        // - remote_local_endpoint: 2 bytes len + string

        var payload_buf: [1024]u8 = undefined;
        var payload_stream = std.io.fixedBufferStream(&payload_buf);
        const writer = payload_stream.writer();

        // 目标机器 ID
        try writer.writeInt(u16, @intCast(target_id.len), .big);
        try writer.writeAll(target_id);

        // 源 NAT 类型
        try writer.writeByte(@intFromEnum(self.local_nat_type));

        // 传输方式
        try writer.writeByte(@intFromEnum(transport));

        // 方向 (正向)
        try writer.writeByte(@intFromEnum(types.TunnelDirection.forward));

        // 事务 ID
        try writer.writeAll(&transaction_id);

        // 流 ID
        try writer.writeInt(u32, 0, .big);

        // SSL
        try writer.writeByte(if (self.config.tls_enabled) 1 else 0);

        // 同局域网标志 (简单判断：如果 public 相同且 local 可互通)
        const same_lan: bool = false; // TODO: 实现同局域网检测
        try writer.writeByte(if (same_lan) 1 else 0);

        // 我方公网端点字符串
        var my_public_str_buf: [64]u8 = undefined;
        const my_public_str = if (my_public) |addr| formatAddress(addr, &my_public_str_buf) else "";
        try writer.writeInt(u16, @intCast(my_public_str.len), .big);
        if (my_public_str.len > 0) try writer.writeAll(my_public_str);

        // 我方本地端点字符串
        var my_local_str_buf: [64]u8 = undefined;
        const my_local_str = if (my_local) |addr| formatAddress(addr, &my_local_str_buf) else "";
        try writer.writeInt(u16, @intCast(my_local_str.len), .big);
        if (my_local_str.len > 0) try writer.writeAll(my_local_str);

        // 对方公网端点字符串（服务器转发时会交换）
        var remote_public_str_buf: [64]u8 = undefined;
        const remote_public_str = if (remote_public) |addr| formatAddress(addr, &remote_public_str_buf) else "";
        try writer.writeInt(u16, @intCast(remote_public_str.len), .big);
        if (remote_public_str.len > 0) try writer.writeAll(remote_public_str);

        // 对方本地端点字符串
        var remote_local_str_buf: [64]u8 = undefined;
        const remote_local_str = if (remote_local) |addr| formatAddress(addr, &remote_local_str_buf) else "";
        try writer.writeInt(u16, @intCast(remote_local_str.len), .big);
        if (remote_local_str.len > 0) try writer.writeAll(remote_local_str);

        const payload = payload_stream.getWritten();

        const header = protocol.MessageHeader{
            .magic = protocol.PROTOCOL_MAGIC,
            .version = protocol.PROTOCOL_VERSION,
            .msg_type = .punch_begin,
            .data_length = @intCast(payload.len),
            .sequence = self.nextSequence(),
        };

        var header_buf: [protocol.MessageHeader.SIZE]u8 = undefined;
        try header.serialize(&header_buf);

        // 合并 header 和 payload
        var send_buf: [1280]u8 = undefined;
        @memcpy(send_buf[0..protocol.MessageHeader.SIZE], &header_buf);
        @memcpy(send_buf[protocol.MessageHeader.SIZE .. protocol.MessageHeader.SIZE + payload.len], payload);
        const total_len = protocol.MessageHeader.SIZE + payload.len;

        // 使用 TLS 或普通 socket 发送
        if (self.tls_conn) |*tc| {
            _ = try tc.send(send_buf[0..total_len]);
        } else {
            _ = try posix.send(self.server_socket.?, send_buf[0..total_len], 0);
        }

        log.info("已发送打洞开始消息到 {s}", .{target_id});
        log.info("  我方端点: 本地={s}, 公网={s}", .{ my_local_str, my_public_str });
        log.info("  对方端点: 本地={s}, 公网={s}", .{ remote_local_str, remote_public_str });
    }

    /// 运行消息循环
    pub fn runLoop(self: *Self) !void {
        const sock = self.server_socket orelse return error.NotConnected;

        var recv_buf: [4096]u8 = undefined;
        var last_heartbeat = std.time.timestamp();

        var last_cleanup: i64 = 0;

        while (true) {
            // 检查心跳
            const now = std.time.timestamp();
            if (now - last_heartbeat >= self.config.heartbeat_interval) {
                self.sendHeartbeat() catch {};
                last_heartbeat = now;
            }

            // 定期清理超时的待处理请求
            const now_ms = std.time.milliTimestamp();
            if (now_ms - last_cleanup >= 5000) { // 每 5 秒检查一次
                self.cleanupExpiredPendingRequests();
                last_cleanup = now_ms;
            }

            // 设置接收超时
            net_utils.setRecvTimeout(sock, 1000) catch {};

            // 使用 TLS 或普通 socket 接收
            const recv_len = if (self.tls_conn) |*tc| blk: {
                break :blk tc.recv(&recv_buf) catch |e| {
                    if (e == error.WouldBlock) continue;
                    // TLS 超时也视为 WouldBlock
                    if (e == error.ConnectionTimedOut) continue;
                    // 连接被重置
                    if (e == error.ConnectionResetByPeer) {
                        log.warn("连接被服务器重置", .{});
                        return error.ConnectionClosed;
                    }
                    return e;
                };
            } else blk: {
                break :blk posix.recv(sock, &recv_buf, 0) catch |e| {
                    if (e == error.WouldBlock) continue;
                    if (e == error.ConnectionTimedOut) continue;
                    if (e == error.ConnectionResetByPeer) {
                        log.warn("连接被服务器重置", .{});
                        return error.ConnectionClosed;
                    }
                    return e;
                };
            };

            if (recv_len == 0) {
                log.warn("服务器断开连接", .{});
                return error.ConnectionClosed;
            }

            if (recv_len < protocol.MessageHeader.SIZE) continue;

            const header = protocol.MessageHeader.parse(recv_buf[0..protocol.MessageHeader.SIZE]) catch continue;

            switch (header.msg_type) {
                .heartbeat_response => {
                    // 心跳响应，解析服务器时间
                    const hb_payload = recv_buf[protocol.MessageHeader.SIZE..recv_len];
                    if (hb_payload.len >= 8) {
                        const server_time = std.mem.readInt(i64, hb_payload[0..8], .big);
                        const local_time = std.time.milliTimestamp();
                        const new_offset = server_time - local_time;

                        // 获取本地时区偏移（秒），用于转换为本地时间显示
                        const tz_offset_secs = getLocalTimezoneOffset();

                        // 转换为可读的本地时区时间格式
                        const local_timestamp_secs: i64 = @intCast(@divTrunc(local_time, 1000));
                        const server_timestamp_secs: i64 = @intCast(@divTrunc(server_time, 1000));

                        // 应用时区偏移
                        const local_adjusted: u64 = @intCast(local_timestamp_secs + tz_offset_secs);
                        const server_adjusted: u64 = @intCast(server_timestamp_secs + tz_offset_secs);

                        const local_epoch = std.time.epoch.EpochSeconds{ .secs = local_adjusted };
                        const server_epoch = std.time.epoch.EpochSeconds{ .secs = server_adjusted };
                        const local_year_day = local_epoch.getEpochDay().calculateYearDay();
                        const server_year_day = server_epoch.getEpochDay().calculateYearDay();
                        const local_month_day = local_year_day.calculateMonthDay();
                        const server_month_day = server_year_day.calculateMonthDay();
                        const local_day_secs = local_epoch.getDaySeconds();
                        const server_day_secs = server_epoch.getDaySeconds();

                        // 每次收到心跳响应都打印时间对比信息（本地时区时间）
                        log.info("心跳响应 - 本地时间: {d}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}, 服务端时间: {d}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}, 偏差: {d}ms", .{
                            local_year_day.year,
                            local_month_day.month.numeric(),
                            local_month_day.day_index + 1,
                            local_day_secs.getHoursIntoDay(),
                            local_day_secs.getMinutesIntoHour(),
                            local_day_secs.getSecondsIntoMinute(),
                            server_year_day.year,
                            server_month_day.month.numeric(),
                            server_month_day.day_index + 1,
                            server_day_secs.getHoursIntoDay(),
                            server_day_secs.getMinutesIntoHour(),
                            server_day_secs.getSecondsIntoMinute(),
                            new_offset,
                        });

                        // 如果是第一次同步，或者偏移量变化超过 100ms，则更新
                        if (!self.time_synced or @abs(new_offset - self.server_time_offset) > 100) {
                            self.server_time_offset = new_offset;
                            self.time_synced = true;

                            // 同步日志模块的时间偏移
                            log.setServerTimeOffset(new_offset);

                            log.debug("时间同步更新: 新偏移={d}ms", .{new_offset});
                        }
                    }
                },
                .punch_begin => {
                    // 收到打洞开始通知
                    const loop_payload = recv_buf[protocol.MessageHeader.SIZE..recv_len];
                    const begin = protocol.PunchBegin.parse(loop_payload) orelse continue;

                    // 显示详细的打洞请求信息和 NAT 分析
                    log.info("", .{});
                    log.info("╔══════════════════════════════════════════════════════════════╗", .{});
                    if (begin.same_lan) {
                        log.info("║              收到内网直连请求                                 ║", .{});
                    } else {
                        log.info("║              收到打洞请求                                     ║", .{});
                    }
                    log.info("╠══════════════════════════════════════════════════════════════╣", .{});
                    log.info("║ 对方节点 ID:   {s}", .{begin.source_machine_id});
                    log.info("║ 对方 NAT 类型: {s}", .{begin.source_nat_type.description()});
                    log.info("║ 本地 NAT 类型: {s}", .{self.local_nat_type.description()});
                    log.info("║ 打洞方向:      {s}", .{if (begin.direction == .forward) "正向 (我方主动)" else "反向 (我方被动)"});
                    log.info("║ 传输方式:      {s}", .{begin.transport.description()});
                    log.info("║ 需要 SSL:      {s}", .{if (begin.ssl) "是" else "否"});
                    log.info("║ 同一局域网:    {s}", .{if (begin.same_lan) "✓ 是" else "✗ 否"});
                    if (begin.remote_public_endpoint.len > 0) {
                        log.info("║ 对方公网地址:  {s}", .{begin.remote_public_endpoint});
                    }
                    if (begin.remote_local_endpoint.len > 0) {
                        log.info("║ 对方本地地址:  {s}", .{begin.remote_local_endpoint});
                    }
                    log.info("╠══════════════════════════════════════════════════════════════╣", .{});

                    // NAT 类型兼容性分析
                    if (begin.same_lan) {
                        log.info("║ 连接策略:     ✓ 同局域网，将使用内网地址直连", .{});
                    } else {
                        const can_p2p = self.local_nat_type.canP2P(begin.source_nat_type);
                        if (can_p2p) {
                            log.info("║ NAT 兼容性:    ✓ 可直接 P2P 打洞", .{});
                        } else {
                            log.info("║ NAT 兼容性:    ✗ 难以直接 P2P，需要中继或端口映射", .{});
                        }
                    }
                    log.info("╚══════════════════════════════════════════════════════════════╝", .{});

                    // 调用回调（如果有）
                    if (self.on_punch_request) |callback| {
                        callback(self, &begin);
                    }

                    // 被动方响应打洞 - 必须使用发起方指定的传输方式
                    // 不能自己选择打洞方式，必须配合发起方！
                    log.info("", .{});
                    log.info("响应打洞请求，使用发起方指定的方式: {s}", .{begin.transport.description()});

                    // 解析对方地址（从消息中的 remote_* 字段获取）
                    var remote_endpoints: [4]net.Address = undefined;
                    var endpoint_count: usize = 0;

                    // 从 begin 消息中解析对方地址
                    if (begin.remote_local_endpoint.len > 0) {
                        if (parseEndpointString(begin.remote_local_endpoint)) |addr| {
                            remote_endpoints[endpoint_count] = addr;
                            endpoint_count += 1;
                            const addr_str = log.formatAddress(addr);
                            log.info("  对方本地地址: {s}", .{std.mem.sliceTo(&addr_str, 0)});
                        }
                    }
                    if (begin.remote_public_endpoint.len > 0) {
                        if (parseEndpointString(begin.remote_public_endpoint)) |addr| {
                            remote_endpoints[endpoint_count] = addr;
                            endpoint_count += 1;
                            const addr_str = log.formatAddress(addr);
                            log.info("  对方公网地址: {s}", .{std.mem.sliceTo(&addr_str, 0)});
                        }
                    }

                    if (endpoint_count == 0) {
                        log.err("没有可用的对方端点地址", .{});
                        continue;
                    }

                    // 解析我方应该使用的地址（从消息中的 my_* 字段获取）
                    // 这是发起方通过服务器告诉我应该用的端口
                    var my_local_addr: ?net.Address = null;
                    var my_public_addr: ?net.Address = null;

                    if (begin.my_local_endpoint.len > 0) {
                        if (parseEndpointString(begin.my_local_endpoint)) |addr| {
                            my_local_addr = addr;
                            const addr_str = log.formatAddress(addr);
                            log.info("  我方本地地址(消息指定): {s}", .{std.mem.sliceTo(&addr_str, 0)});
                        }
                    }
                    if (begin.my_public_endpoint.len > 0) {
                        if (parseEndpointString(begin.my_public_endpoint)) |addr| {
                            my_public_addr = addr;
                            const addr_str = log.formatAddress(addr);
                            log.info("  我方公网地址(消息指定): {s}", .{std.mem.sliceTo(&addr_str, 0)});
                        }
                    }

                    // 如果消息中没有指定我方地址，根据传输类型使用对应的已知地址
                    // TCP 打洞使用 tcp_local_addr，UDP 打洞使用 udp_local_addr
                    const local_to_use = my_local_addr orelse blk: {
                        if (begin.transport.protocolType() == .tcp) {
                            break :blk self.tcp_local_addr orelse self.local_addr orelse net.Address.initIp4(.{ 0, 0, 0, 0 }, 0);
                        } else {
                            break :blk self.udp_local_addr orelse self.local_addr orelse net.Address.initIp4(.{ 0, 0, 0, 0 }, 0);
                        }
                    };
                    const public_to_use = my_public_addr orelse blk: {
                        if (begin.transport.protocolType() == .tcp) {
                            break :blk self.tcp_public_addr orelse self.public_addr;
                        } else {
                            break :blk self.public_addr;
                        }
                    };

                    // 解析对方的本地地址和公网地址
                    const remote_local_addr = remote_endpoints[0];
                    const remote_public_addr: ?net.Address = if (endpoint_count > 1) remote_endpoints[1] else null;

                    // C# Linker 逻辑：只有当双方公网 IP 相同时（同一局域网），才尝试连接对方的本地地址
                    var filtered_endpoints: [4]net.Address = undefined;
                    var filtered_count: usize = 0;

                    const same_lan_check = if (public_to_use != null and remote_public_addr != null) blk: {
                        const my_ip = getIpBytes(public_to_use.?);
                        const remote_ip = getIpBytes(remote_public_addr.?);
                        break :blk std.mem.eql(u8, &my_ip, &remote_ip);
                    } else false;

                    // 如果消息中明确标记 same_lan，或者我们检测到公网 IP 相同，则认为是同一局域网
                    const is_same_lan = begin.same_lan or same_lan_check;

                    if (is_same_lan) {
                        log.info("检测到双方在同一局域网，将尝试连接本地地址", .{});
                        filtered_endpoints[filtered_count] = remote_local_addr;
                        filtered_count += 1;
                        if (remote_public_addr) |pub_addr| {
                            filtered_endpoints[filtered_count] = pub_addr;
                            filtered_count += 1;
                        }
                    } else {
                        log.info("检测到双方在不同网络，只尝试连接公网地址", .{});
                        if (remote_public_addr) |pub_addr| {
                            filtered_endpoints[filtered_count] = pub_addr;
                            filtered_count += 1;
                        } else {
                            log.warn("没有公网地址，退回到使用本地地址", .{});
                            filtered_endpoints[filtered_count] = remote_local_addr;
                            filtered_count += 1;
                        }
                    }

                    // 打印过滤后的端点列表
                    log.info("过滤后的目标端点数量: {d}", .{filtered_count});
                    for (filtered_endpoints[0..filtered_count], 0..) |ep, i| {
                        const ep_str = log.formatAddress(ep);
                        log.info("  过滤后端点 [{d}]: {s}", .{ i, std.mem.sliceTo(&ep_str, 0) });
                    }

                    // 构造传输信息
                    // direction 保持原样：forward 表示我是发起方，reverse 表示我是被动方
                    const transport_info = types.TunnelTransportInfo{
                        .flow_id = begin.flow_id,
                        .direction = begin.direction,
                        .local = types.EndpointInfo{
                            .machine_id = self.assigned_id,
                            .machine_name = self.config.machine_name,
                            .nat_type = self.local_nat_type,
                            // 关键：使用消息中指定的地址，而不是当前的 self.udp_local_addr
                            // 因为并发打洞时 self.udp_local_addr 可能已经变化
                            .local = local_to_use,
                            .local_ips = &.{},
                            .remote = public_to_use,
                            .port_map_wan = self.config.port_map_wan,
                            .port_map_lan = 0,
                            .route_level = 8,
                        },
                        .remote = types.EndpointInfo{
                            .machine_id = begin.source_machine_id,
                            .machine_name = "",
                            .nat_type = begin.source_nat_type,
                            .local = remote_local_addr,
                            .local_ips = &.{},
                            .remote = remote_public_addr,
                            .port_map_wan = 0,
                            .port_map_lan = 0,
                            .route_level = 8,
                        },
                        .remote_endpoints = filtered_endpoints[0..filtered_count],
                        .ssl = begin.ssl,
                    };

                    const start_time = std.time.milliTimestamp();

                    // 根据方向选择正确的方法：
                    // - forward: 我是发起方，用 connect()
                    // - reverse: 我是被动方，用 onBegin()
                    const connection = if (begin.direction == .forward)
                        self.transport_manager.connect(begin.transport, &transport_info) catch |e| {
                            log.err("发起打洞失败: {any}", .{e});
                            continue;
                        }
                    else
                        self.transport_manager.onBegin(begin.transport, &transport_info) catch |e| {
                            log.err("响应打洞失败: {any}", .{e});
                            continue;
                        };

                    const duration = @as(u64, @intCast(std.time.milliTimestamp() - start_time));

                    if (connection) |conn| {
                        const remote_addr_str = log.formatAddress(conn.info.remote_endpoint);
                        log.info("========== 打洞成功 ==========", .{});
                        log.info("传输方式: {s}", .{begin.transport.description()});
                        log.info("耗时: {d} ms", .{duration});
                        log.info("远程端点: {s}", .{std.mem.sliceTo(&remote_addr_str, 0)});
                        log.info("方向: {s}", .{if (begin.direction == .forward) "正向 (我方主动)" else "反向 (我方被动)"});
                        log.info("==============================", .{});

                        var mutable_conn = conn;
                        const hello_msg = "Hello";
                        var hello_recv_buf: [256]u8 = undefined;

                        // 清空 UDP 缓冲区中的打洞协议残留数据
                        // 循环读取直到没有数据或超时
                        var flush_count: u32 = 0;
                        while (flush_count < 10) : (flush_count += 1) {
                            if (mutable_conn.recvWithTimeout(&hello_recv_buf, 100)) |flush_len| {
                                if (flush_len == 0) break;
                                // 检查是否是协议数据（以 "linker.zig" 开头）
                                if (flush_len >= 10 and std.mem.startsWith(u8, hello_recv_buf[0..flush_len], "linker.zig")) {
                                    log.debug("清除协议残留数据: {s}", .{hello_recv_buf[0..flush_len]});
                                    continue;
                                }
                                // 不是协议数据，可能是对方的 Hello，退出清空循环
                                break;
                            } else |_| {
                                // 超时，缓冲区已空
                                break;
                            }
                        }

                        // 双向消息测试：根据方向决定先发还是先收
                        // forward (主动方): 先发 Hello，再收 Hello
                        // reverse (被动方): 先收 Hello，再发 Hello
                        if (begin.direction == .forward) {
                            // 主动方：先发后收
                            log.info(">>> [{s}] -> [{s}] 发送消息: {s}", .{ self.assigned_id, begin.source_machine_id, hello_msg });
                            _ = mutable_conn.send(hello_msg) catch |e| {
                                log.err("发送消息失败: {any}", .{e});
                            };

                            // 等待对方 Hello
                            var got_hello = false;
                            var recv_attempts: u32 = 0;
                            while (recv_attempts < 50 and !got_hello) : (recv_attempts += 1) {
                                if (mutable_conn.recvWithTimeout(&hello_recv_buf, 100)) |hello_len| {
                                    if (hello_len > 0) {
                                        if (hello_len >= 10 and std.mem.startsWith(u8, hello_recv_buf[0..hello_len], "linker.zig")) {
                                            log.debug("跳过协议数据: {s}", .{hello_recv_buf[0..hello_len]});
                                            continue;
                                        }
                                        log.info("<<< [{s}] <- [{s}] 收到消息: {s}", .{ self.assigned_id, begin.source_machine_id, hello_recv_buf[0..hello_len] });
                                        got_hello = true;
                                    }
                                } else |_| {}
                            }
                            if (!got_hello) {
                                log.warn("接收对方消息超时", .{});
                            }
                        } else {
                            // 被动方：先收后发（增加等待时间，等待主动方打洞完成并发送 Hello）
                            // 被动方打洞可能比主动方更早完成，需要等待主动方
                            var got_hello = false;
                            var recv_attempts: u32 = 0;
                            while (recv_attempts < 80 and !got_hello) : (recv_attempts += 1) {
                                if (mutable_conn.recvWithTimeout(&hello_recv_buf, 100)) |hello_len| {
                                    if (hello_len > 0) {
                                        if (hello_len >= 10 and std.mem.startsWith(u8, hello_recv_buf[0..hello_len], "linker.zig")) {
                                            log.debug("跳过协议数据: {s}", .{hello_recv_buf[0..hello_len]});
                                            continue;
                                        }
                                        log.info("<<< [{s}] <- [{s}] 收到消息: {s}", .{ self.assigned_id, begin.source_machine_id, hello_recv_buf[0..hello_len] });
                                        got_hello = true;
                                    }
                                } else |_| {}
                            }
                            if (!got_hello) {
                                log.warn("接收对方消息超时", .{});
                            }

                            // 收到 Hello 后发送回复
                            log.info(">>> [{s}] -> [{s}] 发送消息: {s}", .{ self.assigned_id, begin.source_machine_id, hello_msg });
                            _ = mutable_conn.send(hello_msg) catch |e| {
                                log.err("发送消息失败: {any}", .{e});
                            };
                        }

                        log.info("隧道连接已建立，保持活跃状态", .{});
                        // 将连接保存到连接池
                        self.saveConnection(begin.source_machine_id, mutable_conn);
                    } else {
                        log.err("========== 打洞失败 ==========", .{});
                        log.err("传输方式: {s}", .{begin.transport.description()});
                        log.err("耗时: {d} ms", .{duration});
                        log.err("==============================", .{});
                    }
                },
                .peer_online => {
                    // 收到节点上线通知
                    const loop_payload = recv_buf[protocol.MessageHeader.SIZE..recv_len];
                    const peer_info = protocol.PeerOnline.parse(loop_payload) orelse continue;

                    log.info("", .{});
                    log.info("╔══════════════════════════════════════════════════════════════╗", .{});
                    log.info("║              新节点上线                                       ║", .{});
                    log.info("╠══════════════════════════════════════════════════════════════╣", .{});
                    log.info("║ ID:   {s}", .{peer_info.machine_id});
                    log.info("║ 名称: {s}", .{peer_info.machine_name});
                    log.info("║ NAT:  {s}", .{peer_info.nat_type.description()});
                    log.info("╚══════════════════════════════════════════════════════════════╝", .{});

                    // 调用回调
                    if (self.on_peer_online) |callback| {
                        callback(self, &peer_info);
                    }

                    // 自动与新上线节点打洞（使用异步流程）
                    log.info("正在尝试与 {s} 打洞...", .{peer_info.machine_id});
                    self.initiatePunch(peer_info.machine_id, .tcp_p2p_nat) catch |e| {
                        log.err("发起打洞失败: {any}", .{e});
                    };
                },
                .peer_offline => {
                    // 收到节点下线通知
                    const loop_payload = recv_buf[protocol.MessageHeader.SIZE..recv_len];
                    const peer_info = protocol.PeerOffline.parse(loop_payload) orelse continue;

                    log.info("", .{});
                    log.info("┌──────────────────────────────────────────────────────────────┐", .{});
                    log.info("│ 节点下线: {s}", .{peer_info.machine_id});
                    log.info("└──────────────────────────────────────────────────────────────┘", .{});

                    // 关闭与该节点的连接，释放资源
                    self.closeConnectionByMachineId(peer_info.machine_id);

                    // 调用回调
                    if (self.on_peer_offline) |callback| {
                        callback(self, &peer_info);
                    }
                },
                .get_wan_port => {
                    // 收到获取端口请求，需要刷新端口并响应
                    const loop_payload = recv_buf[protocol.MessageHeader.SIZE..recv_len];
                    if (loop_payload.len < 2) continue;

                    const requester_id_len = std.mem.readInt(u16, loop_payload[0..2], .big);
                    if (loop_payload.len < 2 + requester_id_len) continue;
                    const requester_id = loop_payload[2 .. 2 + requester_id_len];

                    // 解析协议类型（可选，兼容旧协议）
                    var protocol_type: u8 = 0; // 默认 UDP
                    if (loop_payload.len >= 2 + requester_id_len + 1) {
                        protocol_type = loop_payload[2 + requester_id_len];
                    }

                    log.info("收到端口查询请求，来自: {s}, 协议类型: {d}", .{ requester_id, protocol_type });

                    // 发送端口响应（根据协议类型刷新对应端口）
                    self.sendGetWanPortResponse(requester_id, protocol_type) catch |e| {
                        log.err("发送端口响应失败: {any}", .{e});
                    };
                },
                .get_wan_port_response => {
                    // 收到端口响应
                    const loop_payload = recv_buf[protocol.MessageHeader.SIZE..recv_len];
                    if (loop_payload.len < 2) continue;

                    var offset: usize = 0;

                    // 源机器 ID
                    const source_id_len = std.mem.readInt(u16, loop_payload[offset..][0..2], .big);
                    offset += 2;
                    if (loop_payload.len < offset + source_id_len) continue;
                    const source_id = loop_payload[offset .. offset + source_id_len];
                    offset += source_id_len;

                    // 本地端点
                    if (loop_payload.len < offset + 2) continue;
                    const local_len = std.mem.readInt(u16, loop_payload[offset..][0..2], .big);
                    offset += 2;
                    if (loop_payload.len < offset + local_len) continue;
                    const remote_local_str = loop_payload[offset .. offset + local_len];
                    offset += local_len;

                    // 公网端点
                    if (loop_payload.len < offset + 2) continue;
                    const public_len = std.mem.readInt(u16, loop_payload[offset..][0..2], .big);
                    offset += 2;
                    if (loop_payload.len < offset + public_len) continue;
                    const remote_public_str = loop_payload[offset .. offset + public_len];

                    log.info("收到 {s} 的端口响应: 本地={s}, 公网={s}", .{ source_id, remote_local_str, remote_public_str });

                    // 查找待处理的打洞请求
                    var pending_request: ?PendingPunchRequest = null;
                    {
                        self.pending_mutex.lock();
                        defer self.pending_mutex.unlock();

                        if (self.pending_punch_requests.fetchRemove(source_id)) |kv| {
                            pending_request = kv.value;
                            self.allocator.free(kv.key);
                        }
                    }

                    if (pending_request) |req| {
                        defer self.allocator.free(req.target_id);

                        log.info("找到待处理的打洞请求，继续打洞流程...", .{});

                        // 解析远程端点
                        const remote_local = net_utils.parseEndpointString(remote_local_str);
                        const remote_public = net_utils.parseEndpointString(remote_public_str);

                        // 发送包含双方端口信息的打洞开始消息给服务器转发给对方
                        self.sendPunchBeginWithPorts(
                            req.target_id,
                            req.transport,
                            req.transaction_id,
                            req.local_endpoint,
                            req.public_endpoint,
                            remote_local,
                            remote_public,
                        ) catch |e| {
                            log.err("发送打洞开始消息失败: {any}", .{e});
                            continue;
                        };

                        // 重要：发送 Begin 消息后等待一小段时间，让被动方有时间收到消息并准备好
                        // 这对 TCP 同时打开非常关键，两边需要几乎同时发送 SYN
                        // C# Linker 在 Reverse 方向时也有类似的 50ms 延迟
                        std.Thread.sleep(50 * std.time.ns_per_ms);

                        // 发起方自己也要开始打洞！
                        // 构造远程端点列表
                        var remote_endpoints: [2]net.Address = undefined;
                        var endpoint_count: usize = 0;
                        if (remote_local) |addr| {
                            remote_endpoints[endpoint_count] = addr;
                            endpoint_count += 1;
                        }
                        if (remote_public) |addr| {
                            remote_endpoints[endpoint_count] = addr;
                            endpoint_count += 1;
                        }

                        if (endpoint_count == 0) {
                            log.err("没有可用的远程端点", .{});
                            continue;
                        }

                        // 构造传输信息
                        const transport_info = types.TunnelTransportInfo{
                            .flow_id = 0,
                            .direction = .forward, // 发起方是正向
                            .local = types.EndpointInfo{
                                .machine_id = self.assigned_id,
                                .machine_name = self.config.machine_name,
                                .nat_type = self.local_nat_type,
                                .local = req.local_endpoint orelse net.Address.initIp4(.{ 0, 0, 0, 0 }, 0),
                                .local_ips = &.{},
                                .remote = req.public_endpoint,
                                .port_map_wan = self.config.port_map_wan,
                                .port_map_lan = 0,
                                .route_level = 8,
                            },
                            .remote = types.EndpointInfo{
                                .machine_id = req.target_id,
                                .machine_name = "",
                                .nat_type = .unknown,
                                .local = remote_endpoints[0],
                                .local_ips = &.{},
                                .remote = if (endpoint_count > 1) remote_endpoints[1] else null,
                                .port_map_wan = 0,
                                .port_map_lan = 0,
                                .route_level = 8,
                            },
                            .remote_endpoints = remote_endpoints[0..endpoint_count],
                            .ssl = false,
                        };

                        log.info("发起方开始打洞连接...", .{});
                        const start_time = std.time.milliTimestamp();

                        // 发起方调用 connect
                        const connection = self.transport_manager.connect(req.transport, &transport_info) catch |e| {
                            log.err("发起打洞失败: {any}", .{e});
                            continue;
                        };

                        const duration = @as(u64, @intCast(std.time.milliTimestamp() - start_time));

                        if (connection) |conn| {
                            const remote_addr_str = log.formatAddress(conn.info.remote_endpoint);
                            log.info("========== 打洞成功 ==========", .{});
                            log.info("传输方式: {s}", .{req.transport.description()});
                            log.info("耗时: {d} ms", .{duration});
                            log.info("远程端点: {s}", .{std.mem.sliceTo(&remote_addr_str, 0)});
                            log.info("方向: 正向 (我方主动)", .{});
                            log.info("==============================", .{});

                            var mutable_conn = conn;
                            var hello_recv_buf: [256]u8 = undefined;

                            // 清空 UDP 缓冲区中的打洞协议残留数据
                            var flush_count: u32 = 0;
                            while (flush_count < 10) : (flush_count += 1) {
                                if (mutable_conn.recvWithTimeout(&hello_recv_buf, 100)) |flush_len| {
                                    if (flush_len == 0) break;
                                    // 检查是否是协议数据（以 "linker.zig" 开头）
                                    if (flush_len >= 10 and std.mem.startsWith(u8, hello_recv_buf[0..flush_len], "linker.zig")) {
                                        log.debug("清除协议残留数据: {s}", .{hello_recv_buf[0..flush_len]});
                                        continue;
                                    }
                                    // 不是协议数据，可能是对方的 Hello，退出清空循环
                                    break;
                                } else |_| {
                                    // 超时，缓冲区已空
                                    break;
                                }
                            }

                            // 双方都先发送 Hello，再等待接收
                            // 解决打洞完成时间不同步导致的超时问题
                            const hello_msg = "Hello";
                            log.info(">>> [{s}] -> [{s}] 发送消息: {s}", .{ self.assigned_id, req.target_id, hello_msg });
                            _ = mutable_conn.send(hello_msg) catch |e| {
                                log.err("发送消息失败: {any}", .{e});
                            };

                            // 等待对方 Hello，循环接收直到收到非协议数据
                            // 增加等待时间以应对双方打洞完成时间差（最多等待 5 秒）
                            var got_hello = false;
                            var recv_attempts: u32 = 0;
                            while (recv_attempts < 50 and !got_hello) : (recv_attempts += 1) {
                                if (mutable_conn.recvWithTimeout(&hello_recv_buf, 100)) |hello_len| {
                                    if (hello_len > 0) {
                                        // 跳过协议残留数据
                                        if (hello_len >= 10 and std.mem.startsWith(u8, hello_recv_buf[0..hello_len], "linker.zig")) {
                                            log.debug("跳过协议数据: {s}", .{hello_recv_buf[0..hello_len]});
                                            continue;
                                        }
                                        log.info("<<< [{s}] <- [{s}] 收到消息: {s}", .{ self.assigned_id, req.target_id, hello_recv_buf[0..hello_len] });
                                        got_hello = true;
                                    }
                                } else |_| {
                                    // 单次超时，继续等待
                                }
                            }
                            if (!got_hello) {
                                log.warn("接收对方消息超时", .{});
                            }

                            log.info("隧道连接已建立，保持活跃状态", .{});
                            self.saveConnection(req.target_id, mutable_conn);
                        } else {
                            log.err("========== 打洞失败 ==========", .{});
                            log.err("传输方式: {s}", .{req.transport.description()});
                            log.err("耗时: {d} ms", .{duration});
                            log.err("==============================", .{});
                        }
                    } else {
                        log.warn("未找到 {s} 的待处理打洞请求", .{source_id});

                        // 调用回调（如果有）
                        if (self.on_wan_port_response) |callback| {
                            callback(self, source_id, remote_local_str, remote_public_str);
                        }
                    }
                },
                else => {
                    log.debug("收到未处理的消息类型: {any}", .{header.msg_type});
                },
            }
        }
    }

    /// 获取本机 NAT 类型
    pub fn getNatType(self: *const Self) types.NatType {
        return self.local_nat_type;
    }

    /// 获取公网地址
    pub fn getPublicAddress(self: *const Self) ?net.Address {
        return self.public_addr;
    }

    /// 是否已连接
    pub fn isConnected(self: *const Self) bool {
        return self.server_socket != null and self.registered;
    }

    /// 使用对方信息执行打洞 - 根据收到的 PunchBegin 信息执行打洞
    pub fn executePunchWithPeerInfo(self: *Self, begin: *const protocol.PunchBegin) !AutoPunchResult {
        var result = AutoPunchResult{
            .success = false,
            .tried_methods = 0,
            .successful_method = null,
            .connection = null,
            .total_duration_ms = 0,
            .results = undefined,
        };

        const start_time = std.time.milliTimestamp();

        log.info("", .{});
        log.info("╔══════════════════════════════════════════════════════════════╗", .{});
        log.info("║              开始打洞流程                                    ║", .{});
        log.info("╠══════════════════════════════════════════════════════════════╣", .{});
        log.info("║ 目标节点:   {s}", .{begin.source_machine_id});
        log.info("║ 目标 NAT:   {s}", .{begin.source_nat_type.description()});
        log.info("║ 本地 NAT:   {s}", .{self.local_nat_type.description()});
        log.info("║ 打洞方向:   {s}", .{if (begin.direction == .forward) "正向" else "反向"});
        log.info("║ 待尝试方式: {d}", .{self.config.transports.len});
        log.info("╚══════════════════════════════════════════════════════════════╝", .{});
        log.info("", .{});

        var method_idx: usize = 0;
        for (self.config.transports) |transport_config| {
            if (!transport_config.enabled) {
                log.debug("跳过已禁用的打洞方式: {s}", .{transport_config.name});
                continue;
            }

            const transport_type = config_mod.ClientConfiguration.getTransportType(transport_config.name) orelse {
                log.warn("未知的打洞方式: {s}", .{transport_config.name});
                continue;
            };

            if (method_idx >= result.results.len) break;

            result.tried_methods += 1;
            const method_start = std.time.milliTimestamp();

            log.info("┌──────────────────────────────────────────────────────────────┐", .{});
            log.info("│ [{d}/{d}] 尝试: {s}", .{ result.tried_methods, self.config.transports.len, transport_config.name });
            log.info("│ 优先级: {d}, 超时: {d}s, 重试: {d}次", .{
                transport_config.priority,
                transport_config.timeout_seconds,
                transport_config.retry_count,
            });
            log.info("└──────────────────────────────────────────────────────────────┘", .{});

            // 尝试打洞
            var retry: u8 = 0;
            var punch_success = false;
            var punch_connection: ?transport_mod.ITunnelConnection = null;
            var error_msg: []const u8 = "";

            while (retry <= transport_config.retry_count) : (retry += 1) {
                if (retry > 0) {
                    log.info("  重试第 {d}/{d} 次...", .{ retry, transport_config.retry_count });
                    std.Thread.sleep(500 * std.time.ns_per_ms);
                }

                // 执行具体的打洞方式
                const conn_result = self.tryPunchMethod(transport_type, begin, transport_config.timeout_seconds);

                if (conn_result.success) {
                    punch_success = true;
                    punch_connection = conn_result.connection;
                    error_msg = ""; // 成功时清空错误信息
                    log.info("  ✓ {s} 打洞成功!", .{transport_config.name});
                    break;
                } else {
                    error_msg = conn_result.error_message;
                    log.debug("  尝试 {s} 失败: {s}", .{ transport_config.name, error_msg });
                }
            }

            const method_duration = @as(u64, @intCast(std.time.milliTimestamp() - method_start));

            // 记录结果
            result.results[method_idx] = .{
                .transport_name = transport_config.name,
                .success = punch_success,
                .duration_ms = method_duration,
                .error_message = if (punch_success) "" else error_msg, // 成功时不保留错误信息
            };
            method_idx += 1;

            if (punch_success) {
                result.success = true;
                result.successful_method = transport_type;
                result.connection = punch_connection;
                break;
            } else {
                log.warn("  ✗ {s} 失败: {s} ({d}ms)", .{ transport_config.name, error_msg, method_duration });
            }
        }

        result.total_duration_ms = @intCast(std.time.milliTimestamp() - start_time);
        return result;
    }

    /// 尝试具体的打洞方式
    fn tryPunchMethod(self: *Self, transport_type: types.TransportType, begin: *const protocol.PunchBegin, timeout_seconds: u16) PunchResult {
        _ = timeout_seconds;

        // 构建传输信息
        const local_info = types.EndpointInfo{
            // 关键：使用 UDP 本地地址进行打洞，确保端口与 NAT 映射匹配
            .local = self.udp_local_addr orelse self.local_addr orelse net.Address.initIp4(.{ 0, 0, 0, 0 }, 0),
            .local_ips = &.{},
            .machine_id = self.assigned_id,
            .machine_name = self.config.machine_name,
            .route_level = 8,
            .port_map_wan = self.config.port_map_wan,
            .port_map_lan = 0,
            .nat_type = self.local_nat_type,
        };

        // 解析对方地址 - 如果是同局域网，优先使用本地地址
        var remote_endpoints: [2]net.Address = undefined;
        var remote_count: usize = 0;

        if (begin.same_lan) {
            // 同局域网：优先使用本地地址
            if (begin.remote_local_endpoint.len > 0) {
                if (parseEndpointString(begin.remote_local_endpoint)) |addr| {
                    remote_endpoints[remote_count] = addr;
                    remote_count += 1;
                    log.debug("同局域网模式：使用本地地址 {s}", .{begin.remote_local_endpoint});
                }
            }
            // 备选：公网地址
            if (begin.remote_public_endpoint.len > 0) {
                if (parseEndpointString(begin.remote_public_endpoint)) |addr| {
                    remote_endpoints[remote_count] = addr;
                    remote_count += 1;
                }
            }
        } else {
            // 跨网络：优先使用公网地址
            if (begin.remote_public_endpoint.len > 0) {
                if (parseEndpointString(begin.remote_public_endpoint)) |addr| {
                    remote_endpoints[remote_count] = addr;
                    remote_count += 1;
                }
            }
            if (begin.remote_local_endpoint.len > 0) {
                if (parseEndpointString(begin.remote_local_endpoint)) |addr| {
                    remote_endpoints[remote_count] = addr;
                    remote_count += 1;
                }
            }
        }

        if (remote_count == 0) {
            return PunchResult{
                .success = false,
                .error_message = "无法解析对方地址",
                .duration_ms = 0,
            };
        }

        const remote_info = types.EndpointInfo{
            .local = remote_endpoints[0],
            .local_ips = &.{},
            .machine_id = begin.source_machine_id,
            .machine_name = "",
            .route_level = 8,
            .port_map_wan = 0,
            .port_map_lan = 0,
            .nat_type = begin.source_nat_type,
        };

        const transport_info = types.TunnelTransportInfo{
            .transport_name = transport_type,
            .direction = begin.direction,
            .ssl = begin.ssl,
            .local = local_info,
            .remote = remote_info,
            .remote_endpoints = remote_endpoints[0..remote_count],
            .transaction_id = &begin.transaction_id,
            .flow_id = begin.flow_id,
        };

        log.debug("正在尝试 {s} 打洞，方向: {s}，目标地址: {d} 个", .{
            transport_type.description(),
            if (begin.direction == .forward) "正向" else "反向",
            remote_count,
        });

        // 调用传输管理器执行打洞
        const connection = self.transport_manager.connect(transport_type, &transport_info) catch |e| {
            const err_msg = switch (e) {
                error.Timeout, error.WouldBlock => "连接超时",
                error.ConnectionRefused => "连接被拒绝",
                else => "连接失败",
            };
            return PunchResult{
                .success = false,
                .error_message = err_msg,
                .duration_ms = 0,
            };
        };

        if (connection) |conn| {
            // 打洞连接建立成功，执行 Hello 握手验证
            var mutable_conn = conn;
            const is_initiator = (begin.direction == .forward);

            // 如果 Hello 握手已完成（对方已先完成打洞并发送了 Hello），直接返回成功
            if (mutable_conn.info.hello_completed) {
                log.info("Hello 握手已由对方完成，打洞连接已验证可用! ✓", .{});
                return PunchResult{
                    .success = true,
                    .connection = mutable_conn,
                    .error_message = "",
                    .duration_ms = 0,
                };
            }

            log.info("打洞连接已建立，正在执行 Hello 握手验证...", .{});

            const hello_success = mutable_conn.performHelloHandshake(is_initiator, 3000) catch |e| {
                log.err("Hello 握手异常: {any}", .{e});
                mutable_conn.close();
                return PunchResult{
                    .success = false,
                    .error_message = "Hello握手异常",
                    .duration_ms = 0,
                };
            };

            if (hello_success) {
                log.info("Hello 握手成功，打洞连接已验证可用! ✓", .{});
                return PunchResult{
                    .success = true,
                    .connection = mutable_conn,
                    .error_message = "",
                    .duration_ms = 0,
                };
            } else {
                log.warn("Hello 握手失败，连接不可用", .{});
                mutable_conn.close();
                return PunchResult{
                    .success = false,
                    .error_message = "Hello握手失败",
                    .duration_ms = 0,
                };
            }
        }

        return PunchResult{
            .success = false,
            .error_message = "打洞未成功",
            .duration_ms = 0,
        };
    }

    /// 打印打洞结果汇总
    fn printPunchResult(self: *const Self, result: *const AutoPunchResult, begin: *const protocol.PunchBegin) void {
        _ = self;
        log.info("", .{});
        log.info("╔══════════════════════════════════════════════════════════════╗", .{});
        if (result.success) {
            log.info("║           打洞完成 - 成功 ✓                                   ║", .{});
        } else {
            log.info("║           打洞完成 - 失败 ✗                                   ║", .{});
        }
        log.info("╠══════════════════════════════════════════════════════════════╣", .{});
        log.info("║ 目标节点:     {s}", .{begin.source_machine_id});
        log.info("║ 对方 NAT:     {s}", .{begin.source_nat_type.description()});
        log.info("║ 尝试方式数:   {d}", .{result.tried_methods});
        log.info("║ 总耗时:       {d} ms", .{result.total_duration_ms});
        if (result.successful_method) |method| {
            log.info("║ 成功方式:     {s}", .{method.description()});
        }
        log.info("╠══════════════════════════════════════════════════════════════╣", .{});
        log.info("║ 各方式尝试结果:", .{});

        var i: usize = 0;
        while (i < result.tried_methods and i < result.results.len) : (i += 1) {
            const r = result.results[i];
            const status = if (r.success) "✓" else "✗";
            if (r.error_message.len > 0) {
                log.info("║   {s} {s}: {d}ms - {s}", .{ status, r.transport_name, r.duration_ms, r.error_message });
            } else {
                log.info("║   {s} {s}: {d}ms", .{ status, r.transport_name, r.duration_ms });
            }
        }
        log.info("╚══════════════════════════════════════════════════════════════╝", .{});
    }

    /// 自动打洞 - 按配置文件中的优先级顺序尝试所有打洞方式
    pub fn autoPunch(self: *Self, target_id: []const u8, transports: []const config_mod.TransportConfig) !AutoPunchResult {
        var result = AutoPunchResult{
            .success = false,
            .tried_methods = 0,
            .successful_method = null,
            .connection = null,
            .total_duration_ms = 0,
            .results = undefined,
        };

        const start_time = std.time.milliTimestamp();

        log.info("", .{});
        log.info("╔══════════════════════════════════════════════════════════════╗", .{});
        log.info("║              开始自动打洞                                    ║", .{});
        log.info("╠══════════════════════════════════════════════════════════════╣", .{});
        log.info("║ 目标节点: {s}", .{target_id});
        log.info("║ 待尝试方式数: {d}", .{transports.len});
        log.info("╚══════════════════════════════════════════════════════════════╝", .{});
        log.info("", .{});

        var method_idx: usize = 0;
        for (transports) |transport_config| {
            if (!transport_config.enabled) {
                log.debug("跳过已禁用的打洞方式: {s}", .{transport_config.name});
                continue;
            }

            const transport_type = config_mod.ClientConfiguration.getTransportType(transport_config.name) orelse {
                log.warn("未知的打洞方式: {s}", .{transport_config.name});
                continue;
            };

            if (method_idx >= result.results.len) break;

            result.tried_methods += 1;
            const method_start = std.time.milliTimestamp();

            log.info("", .{});
            log.info("┌──────────────────────────────────────────────────────────────┐", .{});
            log.info("│ [{d}/{d}] 尝试打洞方式: {s}", .{ result.tried_methods, transports.len, transport_config.name });
            log.info("│ 优先级: {d}, 超时: {d}s, 重试: {d}次", .{
                transport_config.priority,
                transport_config.timeout_seconds,
                transport_config.retry_count,
            });
            log.info("└──────────────────────────────────────────────────────────────┘", .{});

            // 尝试打洞（带重试）
            var retry: u8 = 0;
            var punch_result: PunchResult = undefined;
            while (retry <= transport_config.retry_count) : (retry += 1) {
                if (retry > 0) {
                    log.info("  重试第 {d}/{d} 次...", .{ retry, transport_config.retry_count });
                }

                punch_result = self.requestPunch(target_id, transport_type) catch |e| {
                    log.err("  打洞请求异常: {any}", .{e});
                    punch_result = PunchResult{
                        .success = false,
                        .error_message = "请求异常",
                        .duration_ms = 0,
                    };
                    continue;
                };

                if (punch_result.success) {
                    break;
                }

                // 短暂等待后重试
                if (retry < transport_config.retry_count) {
                    std.Thread.sleep(500 * std.time.ns_per_ms);
                }
            }

            const method_duration = @as(u64, @intCast(std.time.milliTimestamp() - method_start));

            // 记录结果
            result.results[method_idx] = .{
                .transport_name = transport_config.name,
                .success = punch_result.success,
                .duration_ms = method_duration,
                .error_message = punch_result.error_message,
            };
            method_idx += 1;

            if (punch_result.success) {
                log.info("", .{});
                log.info("╔══════════════════════════════════════════════════════════════╗", .{});
                log.info("║  ✓ 打洞成功!                                                 ║", .{});
                log.info("╠══════════════════════════════════════════════════════════════╣", .{});
                log.info("║ 使用方式: {s}", .{transport_config.name});
                log.info("║ 耗时: {d} ms", .{method_duration});
                log.info("╚══════════════════════════════════════════════════════════════╝", .{});

                result.success = true;
                result.successful_method = transport_type;
                result.connection = punch_result.connection;
                break;
            } else {
                log.warn("  ✗ 打洞失败: {s} (耗时: {d}ms)", .{ punch_result.error_message, method_duration });
            }
        }

        result.total_duration_ms = @intCast(std.time.milliTimestamp() - start_time);

        // 打印最终结果摘要
        log.info("", .{});
        log.info("╔══════════════════════════════════════════════════════════════╗", .{});
        if (result.success) {
            log.info("║              自动打洞完成 - 成功                              ║", .{});
        } else {
            log.info("║              自动打洞完成 - 失败                              ║", .{});
        }
        log.info("╠══════════════════════════════════════════════════════════════╣", .{});
        log.info("║ 尝试方式数: {d}", .{result.tried_methods});
        log.info("║ 总耗时: {d} ms", .{result.total_duration_ms});
        if (result.successful_method) |method| {
            log.info("║ 成功方式: {s}", .{method.name()});
        }
        log.info("╠══════════════════════════════════════════════════════════════╣", .{});
        log.info("║ 详细结果:", .{});
        for (result.results[0..method_idx]) |r| {
            const status = if (r.success) "✓" else "✗";
            log.info("║   {s} {s}: {d}ms {s}", .{ status, r.transport_name, r.duration_ms, r.error_message });
        }
        log.info("╚══════════════════════════════════════════════════════════════╝", .{});

        return result;
    }
};

/// 自动打洞结果
pub const AutoPunchResult = struct {
    /// 是否成功
    success: bool,
    /// 尝试的方式数量
    tried_methods: u32,
    /// 成功的方式
    successful_method: ?types.TransportType,
    /// 连接
    connection: ?transport_mod.ITunnelConnection,
    /// 总耗时
    total_duration_ms: u64,
    /// 每种方式的结果
    results: [8]MethodResult = undefined,

    pub const MethodResult = struct {
        transport_name: []const u8 = "",
        success: bool = false,
        duration_ms: u64 = 0,
        error_message: []const u8 = "",
    };
};

/// 客户端入口函数
pub fn main() !void {
    // 初始化控制台，支持 UTF-8 中文显示
    zzig.Console.setup();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 解析命令行参数
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var config_path: []const u8 = "punch_client.json";
    var list_only = false;
    var cmd_server_addr: ?[]const u8 = null;
    var cmd_server_port: ?u16 = null;
    var cmd_machine_name: ?[]const u8 = null;
    // TLS 相关命令行参数
    var cmd_tls_enabled: ?bool = null;
    var cmd_tls_skip_verify: ?bool = null;

    // 简单参数解析
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            if (i + 1 < args.len) {
                config_path = args[i + 1];
                i += 1;
            }
        } else if (std.mem.eql(u8, arg, "-s") or std.mem.eql(u8, arg, "--server")) {
            if (i + 1 < args.len) {
                const addr_arg = args[i + 1];
                // 支持 host:port 格式
                if (std.mem.lastIndexOfScalar(u8, addr_arg, ':')) |colon_idx| {
                    cmd_server_addr = addr_arg[0..colon_idx];
                    cmd_server_port = std.fmt.parseInt(u16, addr_arg[colon_idx + 1 ..], 10) catch null;
                } else {
                    cmd_server_addr = addr_arg;
                }
                i += 1;
            }
        } else if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--port")) {
            if (i + 1 < args.len) {
                cmd_server_port = std.fmt.parseInt(u16, args[i + 1], 10) catch 18021;
                i += 1;
            }
        } else if (std.mem.eql(u8, arg, "-n") or std.mem.eql(u8, arg, "--name")) {
            if (i + 1 < args.len) {
                cmd_machine_name = args[i + 1];
                i += 1;
            }
        } else if (std.mem.eql(u8, arg, "-l") or std.mem.eql(u8, arg, "--list")) {
            list_only = true;
        } else if (std.mem.eql(u8, arg, "--tls")) {
            // 启用 TLS
            cmd_tls_enabled = true;
        } else if (std.mem.eql(u8, arg, "--no-tls")) {
            // 禁用 TLS
            cmd_tls_enabled = false;
        } else if (std.mem.eql(u8, arg, "--skip-verify") or std.mem.eql(u8, arg, "-k")) {
            // 跳过证书验证 (类似 curl -k)
            cmd_tls_skip_verify = true;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printUsage();
            return;
        }
    }

    // 加载配置文件
    var config_manager = config_mod.ConfigManager.init(allocator, config_path);
    defer config_manager.deinit();

    config_manager.load() catch |e| {
        log.err("加载配置文件失败: {any}", .{e});
        log.info("将使用默认配置", .{});
    };

    // 应用日志配置
    config_manager.applyLogConfig();

    // 命令行参数覆盖配置文件
    const client_config = ClientConfig{
        .server_addr = cmd_server_addr orelse config_manager.config.server_addr,
        .server_port = cmd_server_port orelse config_manager.config.server_port,
        .machine_name = cmd_machine_name orelse config_manager.config.machine_name,
        .machine_id = config_manager.config.machine_id,
        .heartbeat_interval = config_manager.config.heartbeat_interval,
        .port_map_wan = config_manager.config.port_map_wan,
        .auto_detect_nat = config_manager.config.auto_detect_nat,
        // TLS 配置：命令行参数优先于配置文件
        // skip_verify 是 verify_server 的反向逻辑
        .tls_enabled = cmd_tls_enabled orelse config_manager.config.tls.enabled,
        .tls_skip_verify = cmd_tls_skip_verify orelse !config_manager.config.tls.verify_server,
        // 传输方式配置
        .transports = config_manager.config.transports,
        // STUN 服务器配置
        .stun = config_manager.config.stun,
    };

    log.info("", .{});
    log.info("╔══════════════════════════════════════════════════════════════╗", .{});
    log.info("║              打洞客户端启动                                  ║", .{});
    log.info("╚══════════════════════════════════════════════════════════════╝", .{});
    log.info("", .{});

    var client = PunchClient.init(allocator, client_config);
    defer client.deinit();

    try client.connect();

    // 同步服务器时间（在进行任何打洞操作之前）
    _ = client.syncTime() catch |e| {
        log.warn("时间同步失败: {any}，将继续运行但时间可能不准确", .{e});
    };

    if (list_only) {
        // 只列出在线节点
        var peers = try client.listPeers(allocator);
        defer {
            for (peers.items) |peer| {
                allocator.free(peer.machine_id);
                allocator.free(peer.machine_name);
            }
            peers.deinit(allocator);
        }

        log.info("", .{});
        log.info("┌────────────────────────────────────────────────────────────────┐", .{});
        log.info("│                    在线节点列表                                │", .{});
        log.info("├────┬──────────────────┬──────────────────┬─────────────────────┤", .{});
        log.info("│ #  │ ID               │ 名称             │ NAT类型             │", .{});
        log.info("├────┼──────────────────┼──────────────────┼─────────────────────┤", .{});

        if (peers.items.len == 0) {
            log.info("│                    (无其他在线节点)                           │", .{});
        } else {
            for (peers.items, 0..) |peer, idx| {
                // 格式化 ID
                var id_buf: [16]u8 = undefined;
                @memset(&id_buf, ' ');
                const id_len = @min(peer.machine_id.len, 16);
                @memcpy(id_buf[0..id_len], peer.machine_id[0..id_len]);

                // 格式化名称
                var name_buf: [16]u8 = undefined;
                @memset(&name_buf, ' ');
                const name_len = @min(peer.machine_name.len, 16);
                @memcpy(name_buf[0..name_len], peer.machine_name[0..name_len]);

                log.info("│ {d: >2} │ {s} │ {s} │ {s: <19} │", .{
                    idx + 1,
                    id_buf,
                    name_buf,
                    peer.nat_type.description(),
                });
            }
        }
        log.info("└────┴──────────────────┴──────────────────┴─────────────────────┘", .{});
        log.info("", .{});
    } else {
        // 进入消息循环，等待服务端协调的打洞请求
        log.info("进入被动模式，等待打洞请求...", .{});
        log.info("新节点上线时将自动发起打洞", .{});
        try client.runLoop();
    }
}

fn printUsage() void {
    const usage =
        \\打洞客户端 (支持配置文件和服务端协调打洞)
        \\
        \\用法: client [选项]
        \\
        \\工作模式:
        \\  启动后连接信令服务器，等待打洞请求。
        \\  当有新节点上线时，会自动发起打洞。
        \\  打洞方式由服务端协调，按配置文件中的优先级依次尝试。
        \\
        \\选项:
        \\  -c, --config <路径>   配置文件路径 (默认: punch_client.json)
        \\  -s, --server <地址>   服务器地址 (覆盖配置文件)
        \\  -p, --port <端口>     服务器端口 (覆盖配置文件)
        \\  -n, --name <名称>     本机名称 (覆盖配置文件)
        \\  -l, --list            列出在线节点
        \\
        \\TLS 选项:
        \\  --tls                 强制启用 TLS 加密 (默认已启用)
        \\  --no-tls              禁用 TLS 加密 (仅用于本地调试)
        \\  -k, --skip-verify     跳过服务器证书验证 (用于自签名证书)
        \\
        \\  -h, --help            显示帮助信息
        \\
        \\示例:
        \\  # 启动客户端，连接服务器
        \\  client -s 192.168.1.100 --no-tls
        \\
        \\  # 列出在线节点
        \\  client -s 192.168.1.100 --no-tls -l
        \\
        \\  # 使用指定配置文件
        \\  client -c /path/to/config.json
        \\
    ;
    std.debug.print("{s}", .{usage});
}

test "ClientConfig defaults" {
    const config = ClientConfig{};
    try std.testing.expectEqual(@as(u16, 18021), config.server_port);
    try std.testing.expect(config.auto_detect_nat);
}

test "PunchClient init and deinit" {
    const allocator = std.testing.allocator;
    var client = PunchClient.init(allocator, .{});
    defer client.deinit();

    try std.testing.expect(!client.isConnected());
    try std.testing.expectEqual(types.NatType.unknown, client.getNatType());
}
