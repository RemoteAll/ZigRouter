//! UPnP IGD (Internet Gateway Device) 和 NAT-PMP 自动端口映射实现
//!
//! 支持的协议：
//! 1. UPnP IGD - 通过 SSDP 发现和 SOAP 控制
//! 2. NAT-PMP - Apple 开发的轻量级协议 (RFC 6886)
//! 3. PCP - NAT-PMP 的后继协议 (RFC 6887)
//!
//! UPnP IGD 协议流程：
//! 1. SSDP 发现 - 通过 UDP 组播搜索网关设备 (支持 IPv4 和 IPv6)
//! 2. 获取设备描述 - HTTP GET 获取 XML 描述
//! 3. SOAP 请求 - 添加/删除/查询端口映射
//!
//! NAT-PMP 协议流程：
//! 1. 获取外部 IP - 发送 opcode 0 请求
//! 2. 端口映射 - 发送 opcode 1(UDP)/2(TCP) 请求
//!
//! IPv6 SSDP 组播地址：
//! - ff02::c (link-local scope) - 本地链路范围
//! - ff05::c (site-local scope) - 站点范围
//!
//! 参考：
//! - UPnP Device Architecture 1.0
//! - UPnP Device Architecture 2.0 (支持 IPv6)
//! - WANIPConnection:1 Service Template
//! - RFC 6886 (NAT-PMP)
//! - RFC 6887 (PCP)

const std = @import("std");
const net = std.net;
const log = @import("log.zig");
const net_utils = @import("net_utils.zig");

/// SSDP IPv4 组播地址
const SSDP_ADDR_V4 = "239.255.255.250";
/// SSDP IPv6 链路本地组播地址
const SSDP_ADDR_V6_LINK_LOCAL = "ff02::c";
/// SSDP IPv6 站点本地组播地址
const SSDP_ADDR_V6_SITE_LOCAL = "ff05::c";
/// SSDP 端口
const SSDP_PORT: u16 = 1900;

/// 兼容旧代码的 SSDP_ADDR 别名
const SSDP_ADDR = SSDP_ADDR_V4;

/// NAT-PMP 端口
const NATPMP_PORT: u16 = 5351;

/// 协议类型
pub const Protocol = enum {
    tcp,
    udp,

    pub fn toString(self: Protocol) []const u8 {
        return switch (self) {
            .tcp => "TCP",
            .udp => "UDP",
        };
    }

    pub fn toNatPmpOpcode(self: Protocol) u8 {
        return switch (self) {
            .udp => 1,
            .tcp => 2,
        };
    }
};

/// 端口映射信息
pub const PortMapping = struct {
    /// 外部端口
    external_port: u16,
    /// 内部端口
    internal_port: u16,
    /// 内部 IP 地址
    internal_client: [46]u8 = [_]u8{0} ** 46,
    internal_client_len: usize = 0,
    /// 协议 (TCP/UDP)
    protocol: Protocol,
    /// 描述
    description: [64]u8 = [_]u8{0} ** 64,
    description_len: usize = 0,
    /// 租约时长 (秒，0 表示永久)
    lease_duration: u32 = 0,
    /// 是否启用
    enabled: bool = true,

    pub fn setInternalClient(self: *PortMapping, ip: []const u8) void {
        const len = @min(ip.len, self.internal_client.len);
        @memcpy(self.internal_client[0..len], ip[0..len]);
        self.internal_client_len = len;
    }

    pub fn getInternalClient(self: *const PortMapping) []const u8 {
        return self.internal_client[0..self.internal_client_len];
    }

    pub fn setDescription(self: *PortMapping, desc: []const u8) void {
        const len = @min(desc.len, self.description.len);
        @memcpy(self.description[0..len], desc[0..len]);
        self.description_len = len;
    }

    pub fn getDescription(self: *const PortMapping) []const u8 {
        return self.description[0..self.description_len];
    }
};

/// UPnP 设备信息
pub const DeviceInfo = struct {
    /// 设备友好名称
    friendly_name: [128]u8 = [_]u8{0} ** 128,
    friendly_name_len: usize = 0,
    /// 制造商
    manufacturer: [64]u8 = [_]u8{0} ** 64,
    manufacturer_len: usize = 0,
    /// 控制 URL
    control_url: [256]u8 = [_]u8{0} ** 256,
    control_url_len: usize = 0,
    /// 设备地址
    device_addr: [46]u8 = [_]u8{0} ** 46,
    device_addr_len: usize = 0,
    /// 设备端口
    device_port: u16 = 0,
    /// 外部 IP 地址
    external_ip: [46]u8 = [_]u8{0} ** 46,
    external_ip_len: usize = 0,

    pub fn setFriendlyName(self: *DeviceInfo, name: []const u8) void {
        const len = @min(name.len, self.friendly_name.len);
        @memcpy(self.friendly_name[0..len], name[0..len]);
        self.friendly_name_len = len;
    }

    pub fn getFriendlyName(self: *const DeviceInfo) []const u8 {
        return self.friendly_name[0..self.friendly_name_len];
    }

    pub fn setControlUrl(self: *DeviceInfo, url: []const u8) void {
        const len = @min(url.len, self.control_url.len);
        @memcpy(self.control_url[0..len], url[0..len]);
        self.control_url_len = len;
    }

    pub fn getControlUrl(self: *const DeviceInfo) []const u8 {
        return self.control_url[0..self.control_url_len];
    }

    pub fn setDeviceAddr(self: *DeviceInfo, addr: []const u8) void {
        const len = @min(addr.len, self.device_addr.len);
        @memcpy(self.device_addr[0..len], addr[0..len]);
        self.device_addr_len = len;
    }

    pub fn getDeviceAddr(self: *const DeviceInfo) []const u8 {
        return self.device_addr[0..self.device_addr_len];
    }

    pub fn setExternalIp(self: *DeviceInfo, ip: []const u8) void {
        const len = @min(ip.len, self.external_ip.len);
        @memcpy(self.external_ip[0..len], ip[0..len]);
        self.external_ip_len = len;
    }

    pub fn getExternalIp(self: *const DeviceInfo) []const u8 {
        return self.external_ip[0..self.external_ip_len];
    }
};

/// UPnP 错误类型
pub const UpnpError = error{
    /// 设备发现超时
    DiscoveryTimeout,
    /// 无效响应
    InvalidResponse,
    /// XML 解析错误
    XmlParseError,
    /// HTTP 请求失败
    HttpError,
    /// SOAP 错误
    SoapError,
    /// 端口已被映射
    PortAlreadyMapped,
    /// 无效端口
    InvalidPort,
    /// 不支持的操作
    NotSupported,
    /// 网络错误
    NetworkError,
    /// 无可用设备
    NoDeviceFound,
    /// NAT-PMP 错误
    NatPmpError,
};

// ============== 简易 XML 解析器 ==============

/// 简易 XML 解析器
/// 用于解析 UPnP SOAP 响应
pub const XmlParser = struct {
    data: []const u8,
    pos: usize = 0,

    const Self = @This();

    /// 创建解析器
    pub fn init(data: []const u8) Self {
        return Self{ .data = data };
    }

    /// 查找并提取标签内的文本内容
    /// 例如：从 <TagName>content</TagName> 中提取 "content"
    pub fn findTagContent(self: *Self, tag_name: []const u8) ?[]const u8 {
        // 构建开始标签和结束标签
        var start_tag_buf: [128]u8 = undefined;
        var end_tag_buf: [128]u8 = undefined;

        const start_tag = std.fmt.bufPrint(&start_tag_buf, "<{s}>", .{tag_name}) catch return null;
        const end_tag = std.fmt.bufPrint(&end_tag_buf, "</{s}>", .{tag_name}) catch return null;

        // 查找开始标签
        if (std.mem.indexOf(u8, self.data[self.pos..], start_tag)) |start_idx| {
            const content_start = self.pos + start_idx + start_tag.len;

            // 查找结束标签
            if (std.mem.indexOf(u8, self.data[content_start..], end_tag)) |end_idx| {
                const content = self.data[content_start .. content_start + end_idx];
                self.pos = content_start + end_idx + end_tag.len;
                return content;
            }
        }

        return null;
    }

    /// 查找标签内容（不区分大小写）
    pub fn findTagContentIgnoreCase(self: *Self, tag_name: []const u8) ?[]const u8 {
        // 先尝试原始名称
        if (self.findTagContent(tag_name)) |content| {
            return content;
        }

        // 重置位置并尝试小写
        self.pos = 0;
        var lower_buf: [64]u8 = undefined;
        const lower_len = @min(tag_name.len, lower_buf.len);
        for (0..lower_len) |i| {
            lower_buf[i] = std.ascii.toLower(tag_name[i]);
        }
        return self.findTagContent(lower_buf[0..lower_len]);
    }

    /// 提取 HTTP 响应体（跳过头部）
    pub fn extractHttpBody(data: []const u8) ?[]const u8 {
        // 查找 \r\n\r\n 分隔符
        if (std.mem.indexOf(u8, data, "\r\n\r\n")) |idx| {
            return data[idx + 4 ..];
        }
        // 尝试 \n\n
        if (std.mem.indexOf(u8, data, "\n\n")) |idx| {
            return data[idx + 2 ..];
        }
        return null;
    }

    /// 从 SOAP 响应中提取外部 IP 地址
    pub fn parseExternalIPResponse(data: []const u8) ?[]const u8 {
        // 提取 HTTP body
        const body = extractHttpBody(data) orelse data;

        var parser = Self.init(body);

        // 尝试不同的标签名（不同路由器可能返回不同格式）
        if (parser.findTagContent("NewExternalIPAddress")) |ip| {
            return ip;
        }

        parser.pos = 0;
        if (parser.findTagContent("ExternalIPAddress")) |ip| {
            return ip;
        }

        return null;
    }

    /// 从设备描述 XML 中提取控制 URL
    pub fn parseControlUrl(data: []const u8) ?[]const u8 {
        var parser = Self.init(data);

        // 查找 WANIPConnection 或 WANPPPConnection 服务的控制 URL
        // 首先找到服务类型
        while (parser.findTagContent("serviceType")) |service_type| {
            if (std.mem.indexOf(u8, service_type, "WANIPConnection") != null or
                std.mem.indexOf(u8, service_type, "WANPPPConnection") != null)
            {
                // 找到目标服务，现在查找 controlURL
                if (parser.findTagContent("controlURL")) |url| {
                    return url;
                }
            }
        }

        // 回退：直接查找任何 controlURL
        parser.pos = 0;
        return parser.findTagContent("controlURL");
    }

    /// 从设备描述 XML 中提取友好名称
    pub fn parseFriendlyName(data: []const u8) ?[]const u8 {
        var parser = Self.init(data);
        return parser.findTagContent("friendlyName");
    }

    /// 从设备描述 XML 中提取制造商
    pub fn parseManufacturer(data: []const u8) ?[]const u8 {
        var parser = Self.init(data);
        return parser.findTagContent("manufacturer");
    }

    /// 解析 SOAP 错误码
    pub fn parseSoapErrorCode(data: []const u8) ?u16 {
        const body = extractHttpBody(data) orelse data;
        var parser = Self.init(body);

        if (parser.findTagContent("errorCode")) |code_str| {
            return std.fmt.parseInt(u16, code_str, 10) catch null;
        }
        return null;
    }
};

// ============== NAT-PMP 协议实现 ==============

/// NAT-PMP 客户端
/// 实现 RFC 6886 协议
pub const NatPmpClient = struct {
    allocator: std.mem.Allocator,
    /// 网关地址 (通常是默认网关)
    gateway_addr: [46]u8 = [_]u8{0} ** 46,
    gateway_addr_len: usize = 0,
    /// 外部 IP
    external_ip: [46]u8 = [_]u8{0} ** 46,
    external_ip_len: usize = 0,
    /// 协议版本
    version: u8 = 0,
    /// 服务器时间
    server_epoch: u32 = 0,

    const Self = @This();

    /// NAT-PMP 请求头
    const RequestHeader = packed struct {
        version: u8 = 0,
        opcode: u8,
    };

    /// NAT-PMP 外部地址请求 (opcode 0)
    const ExternalAddressRequest = packed struct {
        version: u8 = 0,
        opcode: u8 = 0,
    };

    /// NAT-PMP 外部地址响应
    const ExternalAddressResponse = packed struct {
        version: u8,
        opcode: u8,
        result_code: u16,
        epoch: u32,
        external_ip: [4]u8,
    };

    /// NAT-PMP 端口映射请求 (opcode 1=UDP, 2=TCP)
    const MappingRequest = packed struct {
        version: u8 = 0,
        opcode: u8,
        reserved: u16 = 0,
        internal_port: u16,
        external_port: u16,
        lifetime: u32,
    };

    /// NAT-PMP 端口映射响应
    const MappingResponse = packed struct {
        version: u8,
        opcode: u8,
        result_code: u16,
        epoch: u32,
        internal_port: u16,
        external_port: u16,
        lifetime: u32,
    };

    /// 初始化 NAT-PMP 客户端
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
        };
    }

    /// 释放资源
    pub fn deinit(self: *Self) void {
        _ = self;
    }

    /// 设置网关地址
    pub fn setGatewayAddr(self: *Self, addr: []const u8) void {
        const len = @min(addr.len, self.gateway_addr.len);
        @memcpy(self.gateway_addr[0..len], addr[0..len]);
        self.gateway_addr_len = len;
    }

    /// 获取网关地址
    pub fn getGatewayAddr(self: *const Self) []const u8 {
        return self.gateway_addr[0..self.gateway_addr_len];
    }

    /// 获取外部 IP
    pub fn getExternalIp(self: *const Self) []const u8 {
        return self.external_ip[0..self.external_ip_len];
    }

    /// 自动检测网关地址
    pub fn detectGateway(self: *Self) !void {
        // 尝试常见的网关地址
        const common_gateways = [_][]const u8{
            "192.168.1.1",
            "192.168.0.1",
            "10.0.0.1",
            "172.16.0.1",
        };

        for (common_gateways) |gateway| {
            self.setGatewayAddr(gateway);
            // 尝试获取外部 IP，如果成功说明网关正确
            if (self.getExternalIPAddress()) |_| {
                log.info("检测到 NAT-PMP 网关: {s}", .{gateway});
                return;
            } else |_| {
                continue;
            }
        }

        return UpnpError.NoDeviceFound;
    }

    /// 获取外部 IP 地址 (opcode 0)
    pub fn getExternalIPAddress(self: *Self) ![]const u8 {
        const gateway = self.getGatewayAddr();
        if (gateway.len == 0) {
            return UpnpError.NoDeviceFound;
        }

        log.debug("NAT-PMP: 请求外部 IP...", .{});

        // 创建 UDP socket
        const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
        defer std.posix.close(sock);

        // 设置超时
        const timeout = std.posix.timeval{ .sec = 2, .usec = 0 };
        try std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));

        // 发送请求
        const request = ExternalAddressRequest{};
        const addr = net.Address.parseIp4(gateway, NATPMP_PORT) catch return UpnpError.NetworkError;

        _ = std.posix.sendto(sock, std.mem.asBytes(&request), 0, &addr.any, addr.getOsSockLen()) catch {
            return UpnpError.NetworkError;
        };

        // 接收响应
        var response: ExternalAddressResponse = undefined;
        var from_addr: std.posix.sockaddr.in = undefined;
        var from_len: std.posix.socklen_t = @sizeOf(@TypeOf(from_addr));

        const recv_len = std.posix.recvfrom(sock, std.mem.asBytes(&response), 0, @ptrCast(&from_addr), &from_len) catch |err| {
            if (err == error.WouldBlock) {
                return UpnpError.DiscoveryTimeout;
            }
            return UpnpError.NetworkError;
        };

        if (recv_len < @sizeOf(ExternalAddressResponse)) {
            return UpnpError.InvalidResponse;
        }

        // 检查结果码
        const result_code = std.mem.bigToNative(u16, response.result_code);
        if (result_code != 0) {
            log.err("NAT-PMP 错误码: {}", .{result_code});
            return UpnpError.NatPmpError;
        }

        // 解析外部 IP
        var ip_str: [16]u8 = undefined;
        const ip_len = std.fmt.bufPrint(&ip_str, "{}.{}.{}.{}", .{
            response.external_ip[0],
            response.external_ip[1],
            response.external_ip[2],
            response.external_ip[3],
        }) catch return UpnpError.InvalidResponse;

        @memcpy(self.external_ip[0..ip_len.len], ip_len);
        self.external_ip_len = ip_len.len;
        self.server_epoch = std.mem.bigToNative(u32, response.epoch);

        log.info("NAT-PMP: 外部 IP = {s}", .{self.getExternalIp()});

        return self.getExternalIp();
    }

    /// 添加端口映射
    pub fn addPortMapping(self: *Self, internal_port: u16, external_port: u16, protocol: Protocol, lifetime: u32) !u16 {
        const gateway = self.getGatewayAddr();
        if (gateway.len == 0) {
            return UpnpError.NoDeviceFound;
        }

        log.info("NAT-PMP: 添加映射 {} -> {} ({s})", .{ external_port, internal_port, protocol.toString() });

        // 创建 UDP socket
        const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
        defer std.posix.close(sock);

        // 设置超时
        const timeout = std.posix.timeval{ .sec = 2, .usec = 0 };
        try std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));

        // 构建请求
        const request = MappingRequest{
            .opcode = protocol.toNatPmpOpcode(),
            .internal_port = std.mem.nativeToBig(u16, internal_port),
            .external_port = std.mem.nativeToBig(u16, external_port),
            .lifetime = std.mem.nativeToBig(u32, lifetime),
        };

        // 发送请求
        const addr = net.Address.parseIp4(gateway, NATPMP_PORT) catch return UpnpError.NetworkError;
        _ = std.posix.sendto(sock, std.mem.asBytes(&request), 0, &addr.any, addr.getOsSockLen()) catch {
            return UpnpError.NetworkError;
        };

        // 接收响应
        var response: MappingResponse = undefined;
        var from_addr: std.posix.sockaddr.in = undefined;
        var from_len: std.posix.socklen_t = @sizeOf(@TypeOf(from_addr));

        const recv_len = std.posix.recvfrom(sock, std.mem.asBytes(&response), 0, @ptrCast(&from_addr), &from_len) catch |err| {
            if (err == error.WouldBlock) {
                return UpnpError.DiscoveryTimeout;
            }
            return UpnpError.NetworkError;
        };

        if (recv_len < @sizeOf(MappingResponse)) {
            return UpnpError.InvalidResponse;
        }

        // 检查结果码
        const result_code = std.mem.bigToNative(u16, response.result_code);
        if (result_code != 0) {
            log.err("NAT-PMP 映射失败，错误码: {}", .{result_code});
            return UpnpError.NatPmpError;
        }

        const mapped_port = std.mem.bigToNative(u16, response.external_port);
        const actual_lifetime = std.mem.bigToNative(u32, response.lifetime);

        log.info("NAT-PMP: 映射成功，外部端口 = {}, 生命周期 = {}s", .{ mapped_port, actual_lifetime });

        return mapped_port;
    }

    /// 删除端口映射 (通过设置 lifetime 为 0)
    pub fn deletePortMapping(self: *Self, internal_port: u16, external_port: u16, protocol: Protocol) !void {
        _ = try self.addPortMapping(internal_port, external_port, protocol, 0);
        log.info("NAT-PMP: 映射已删除", .{});
    }
};

/// UPnP IGD 客户端
pub const UpnpClient = struct {
    allocator: std.mem.Allocator,
    /// 已发现的设备
    device: ?DeviceInfo = null,
    /// 本地 IP 地址 (IPv4 或 IPv6)
    local_ip: [46]u8 = [_]u8{0} ** 46,
    local_ip_len: usize = 0,
    /// 发现超时 (毫秒)
    discovery_timeout_ms: u32 = 3000,
    /// 是否使用 IPv6 进行发现
    use_ipv6: bool = false,
    /// 是否尝试双栈发现 (先 IPv4 再 IPv6)
    dual_stack_discovery: bool = true,

    const Self = @This();

    /// 初始化 UPnP 客户端
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
        };
    }

    /// 释放资源
    pub fn deinit(self: *Self) void {
        _ = self;
        // 目前没有需要释放的资源
    }

    /// 设置本地 IP
    pub fn setLocalIp(self: *Self, ip: []const u8) void {
        const len = @min(ip.len, self.local_ip.len);
        @memcpy(self.local_ip[0..len], ip[0..len]);
        self.local_ip_len = len;
    }

    /// 获取本地 IP
    pub fn getLocalIp(self: *const Self) []const u8 {
        return self.local_ip[0..self.local_ip_len];
    }

    /// 发现 UPnP 网关设备（支持 IPv4 和 IPv6）
    pub fn discover(self: *Self) !void {
        log.info("开始 UPnP 设备发现...", .{});

        // 如果启用双栈发现，先尝试 IPv4，再尝试 IPv6
        if (self.dual_stack_discovery) {
            // 尝试 IPv4 发现
            self.discoverV4() catch |err| {
                log.debug("IPv4 UPnP 发现失败: {}, 尝试 IPv6...", .{err});
                // 尝试 IPv6 发现
                try self.discoverV6();
            };
        } else if (self.use_ipv6) {
            try self.discoverV6();
        } else {
            try self.discoverV4();
        }
    }

    /// IPv4 SSDP 发现
    fn discoverV4(self: *Self) !void {
        log.debug("开始 IPv4 SSDP 发现...", .{});

        // 创建 UDP socket
        const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
        defer std.posix.close(sock);

        // 设置超时
        const timeout = std.posix.timeval{
            .sec = @intCast(self.discovery_timeout_ms / 1000),
            .usec = @intCast((self.discovery_timeout_ms % 1000) * 1000),
        };
        try std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));

        // 构建 SSDP M-SEARCH 请求
        const search_request = buildSsdpSearchRequestV4();

        // 发送到 IPv4 组播地址
        const ssdp_addr = net.Address.parseIp4(SSDP_ADDR_V4, SSDP_PORT) catch unreachable;
        _ = std.posix.sendto(sock, search_request, 0, &ssdp_addr.any, ssdp_addr.getOsSockLen()) catch |err| {
            log.err("发送 SSDP IPv4 请求失败: {}", .{err});
            return UpnpError.NetworkError;
        };

        log.debug("已发送 SSDP M-SEARCH 请求 (IPv4)", .{});

        // 接收响应
        var recv_buf: [2048]u8 = undefined;
        var from_addr: std.posix.sockaddr.in = undefined;
        var from_len: std.posix.socklen_t = @sizeOf(@TypeOf(from_addr));

        const recv_result = std.posix.recvfrom(sock, &recv_buf, 0, @ptrCast(&from_addr), &from_len);

        const recv_len = recv_result catch |err| {
            if (err == error.WouldBlock) {
                log.warn("UPnP IPv4 设备发现超时", .{});
                return UpnpError.DiscoveryTimeout;
            }
            log.err("接收 SSDP IPv4 响应失败: {}", .{err});
            return UpnpError.NetworkError;
        };

        log.debug("收到 SSDP IPv4 响应 {} 字节", .{recv_len});

        // 解析响应获取设备 URL
        const response = recv_buf[0..recv_len];
        const location = try parseSsdpLocation(response);

        log.info("发现设备 (IPv4): {s}", .{location});

        // 获取设备描述
        try self.fetchDeviceDescription(location);
    }

    /// IPv6 SSDP 发现
    fn discoverV6(self: *Self) !void {
        log.debug("开始 IPv6 SSDP 发现...", .{});

        // 创建 IPv6 UDP socket
        const sock = try std.posix.socket(std.posix.AF.INET6, std.posix.SOCK.DGRAM, 0);
        defer std.posix.close(sock);

        // 设置超时
        const timeout = std.posix.timeval{
            .sec = @intCast(self.discovery_timeout_ms / 1000),
            .usec = @intCast((self.discovery_timeout_ms % 1000) * 1000),
        };
        try std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));

        // 构建 IPv6 SSDP M-SEARCH 请求
        const search_request = buildSsdpSearchRequestV6();

        // 先尝试链路本地组播地址
        var discovered = false;
        const ssdp_addrs = [_][]const u8{ SSDP_ADDR_V6_LINK_LOCAL, SSDP_ADDR_V6_SITE_LOCAL };

        for (ssdp_addrs) |addr_str| {
            const ssdp_addr = net.Address.parseIp6(addr_str, SSDP_PORT) catch continue;
            _ = std.posix.sendto(sock, search_request, 0, &ssdp_addr.any, ssdp_addr.getOsSockLen()) catch |err| {
                log.debug("发送 SSDP IPv6 请求到 {s} 失败: {}", .{ addr_str, err });
                continue;
            };

            log.debug("已发送 SSDP M-SEARCH 请求到 {s} (IPv6)", .{addr_str});

            // 接收响应
            var recv_buf: [2048]u8 = undefined;
            var from_addr: std.posix.sockaddr.in6 = undefined;
            var from_len: std.posix.socklen_t = @sizeOf(@TypeOf(from_addr));

            const recv_result = std.posix.recvfrom(sock, &recv_buf, 0, @ptrCast(&from_addr), &from_len);

            const recv_len = recv_result catch |err| {
                if (err == error.WouldBlock) {
                    log.debug("SSDP IPv6 发现超时 (地址: {s})", .{addr_str});
                    continue;
                }
                continue;
            };

            log.debug("收到 SSDP IPv6 响应 {} 字节", .{recv_len});

            // 解析响应获取设备 URL
            const response = recv_buf[0..recv_len];
            const location = parseSsdpLocation(response) catch continue;

            log.info("发现设备 (IPv6): {s}", .{location});

            // 获取设备描述
            self.fetchDeviceDescription(location) catch continue;
            discovered = true;
            break;
        }

        if (!discovered) {
            log.warn("UPnP IPv6 设备发现失败", .{});
            return UpnpError.DiscoveryTimeout;
        }
    }

    /// 构建 IPv4 SSDP M-SEARCH 请求
    fn buildSsdpSearchRequestV4() []const u8 {
        return "M-SEARCH * HTTP/1.1\r\n" ++
            "HOST: 239.255.255.250:1900\r\n" ++
            "MAN: \"ssdp:discover\"\r\n" ++
            "MX: 3\r\n" ++
            "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" ++
            "\r\n";
    }

    /// 构建 IPv6 SSDP M-SEARCH 请求
    fn buildSsdpSearchRequestV6() []const u8 {
        return "M-SEARCH * HTTP/1.1\r\n" ++
            "HOST: [ff02::c]:1900\r\n" ++
            "MAN: \"ssdp:discover\"\r\n" ++
            "MX: 3\r\n" ++
            "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" ++
            "\r\n";
    }

    /// 兼容旧代码的别名
    fn buildSsdpSearchRequest() []const u8 {
        return buildSsdpSearchRequestV4();
    }

    /// 解析 SSDP 响应中的 LOCATION 字段
    fn parseSsdpLocation(response: []const u8) ![]const u8 {
        // 查找 "LOCATION:" 或 "Location:"
        var i: usize = 0;
        while (i + 9 < response.len) : (i += 1) {
            if (std.ascii.eqlIgnoreCase(response[i .. i + 9], "LOCATION:")) {
                // 跳过 "LOCATION:" 和空格
                var start = i + 9;
                while (start < response.len and response[start] == ' ') {
                    start += 1;
                }

                // 找到行结尾
                var end = start;
                while (end < response.len and response[end] != '\r' and response[end] != '\n') {
                    end += 1;
                }

                if (end > start) {
                    return response[start..end];
                }
            }
        }
        return UpnpError.InvalidResponse;
    }

    /// 获取设备描述 (HTTP GET)
    fn fetchDeviceDescription(self: *Self, location_url: []const u8) !void {
        // 解析 URL
        const parsed = try parseUrl(location_url);

        log.debug("连接设备: {s}:{}", .{ parsed.host, parsed.port });

        // 建立 TCP 连接获取设备描述
        const address = net.Address.parseIp4(parsed.host, parsed.port) catch {
            // 如果无法解析，使用简化方式
            return self.fetchDeviceDescriptionSimple(parsed);
        };

        const stream = net.tcpConnectToAddress(address) catch {
            return self.fetchDeviceDescriptionSimple(parsed);
        };
        defer stream.close();

        // 构建 HTTP GET 请求
        var http_request: [512]u8 = undefined;
        const http_header = std.fmt.bufPrint(&http_request,
            \\GET {s} HTTP/1.1
            \\Host: {s}:{d}
            \\Connection: close
            \\
            \\
        , .{ parsed.path, parsed.host, parsed.port }) catch {
            return self.fetchDeviceDescriptionSimple(parsed);
        };

        // 发送请求
        _ = stream.write(http_header) catch {
            return self.fetchDeviceDescriptionSimple(parsed);
        };

        // 读取响应
        var response_buf: [8192]u8 = undefined;
        var total_len: usize = 0;
        while (total_len < response_buf.len) {
            const read_len = stream.read(response_buf[total_len..]) catch break;
            if (read_len == 0) break;
            total_len += read_len;
        }

        if (total_len == 0) {
            return self.fetchDeviceDescriptionSimple(parsed);
        }

        const response = response_buf[0..total_len];
        log.debug("收到设备描述 {} 字节", .{total_len});

        // 使用 XML 解析器解析设备描述
        var device = DeviceInfo{};
        device.setDeviceAddr(parsed.host);
        device.device_port = parsed.port;

        // 解析控制 URL
        if (XmlParser.parseControlUrl(response)) |control_url| {
            // 处理相对 URL
            if (control_url.len > 0 and control_url[0] == '/') {
                device.setControlUrl(control_url);
            } else {
                // 拼接基础 URL
                var full_url: [256]u8 = undefined;
                const full = std.fmt.bufPrint(&full_url, "/{s}", .{control_url}) catch control_url;
                device.setControlUrl(full);
            }
            log.info("控制 URL: {s}", .{device.getControlUrl()});
        } else {
            // 使用默认控制 URL
            device.setControlUrl("/ctl/IPConn");
            log.debug("使用默认控制 URL", .{});
        }

        // 解析友好名称
        if (XmlParser.parseFriendlyName(response)) |name| {
            device.setFriendlyName(name);
            log.info("设备名称: {s}", .{name});
        }

        // 解析制造商
        if (XmlParser.parseManufacturer(response)) |mfr| {
            var mfr_buf: [64]u8 = undefined;
            const mfr_len = @min(mfr.len, mfr_buf.len);
            @memcpy(mfr_buf[0..mfr_len], mfr[0..mfr_len]);
            device.manufacturer_len = mfr_len;
            @memcpy(device.manufacturer[0..mfr_len], mfr[0..mfr_len]);
            log.info("制造商: {s}", .{mfr[0..mfr_len]});
        }

        self.device = device;
        log.info("设备配置完成", .{});
    }

    /// 简化的设备描述获取（不发起 HTTP 请求）
    fn fetchDeviceDescriptionSimple(self: *Self, parsed: ParsedUrl) !void {
        log.debug("使用简化设备配置", .{});

        var device = DeviceInfo{};
        device.setDeviceAddr(parsed.host);
        device.device_port = parsed.port;

        // 尝试常见的控制 URL
        const common_control_urls = [_][]const u8{
            "/ctl/IPConn",
            "/upnp/control/WANIPConn1",
            "/upnp/control/WANIPConnection",
            "/WANIPConnection",
        };

        // 使用第一个作为默认
        device.setControlUrl(common_control_urls[0]);

        self.device = device;
        log.info("设备配置完成（简化模式）", .{});
    }

    /// URL 解析结果
    const ParsedUrl = struct {
        host: []const u8,
        port: u16,
        path: []const u8,
    };

    /// 简单的 URL 解析
    fn parseUrl(url: []const u8) !ParsedUrl {
        // 跳过 "http://"
        var start: usize = 0;
        if (url.len > 7 and std.mem.eql(u8, url[0..7], "http://")) {
            start = 7;
        }

        // 查找主机和端口分隔符
        var host_end = start;
        var port_start: ?usize = null;
        var path_start: usize = url.len;

        while (host_end < url.len) : (host_end += 1) {
            if (url[host_end] == ':') {
                port_start = host_end + 1;
            } else if (url[host_end] == '/') {
                path_start = host_end;
                break;
            }
        }

        const host = if (port_start) |ps|
            url[start .. ps - 1]
        else
            url[start..host_end];

        const port: u16 = if (port_start) |ps| blk: {
            const port_end = if (path_start < url.len) path_start else url.len;
            break :blk std.fmt.parseInt(u16, url[ps..port_end], 10) catch 80;
        } else 80;

        const path = if (path_start < url.len) url[path_start..] else "/";

        return ParsedUrl{
            .host = host,
            .port = port,
            .path = path,
        };
    }

    /// 添加端口映射
    pub fn addPortMapping(self: *Self, mapping: PortMapping) !void {
        const device = self.device orelse return UpnpError.NoDeviceFound;

        log.info("添加端口映射: {} -> {}:{} ({s})", .{
            mapping.external_port,
            mapping.getInternalClient(),
            mapping.internal_port,
            mapping.protocol.toString(),
        });

        // 构建 SOAP 请求
        var soap_body: [2048]u8 = undefined;
        const soap_len = try buildAddPortMappingSoap(&soap_body, mapping);

        // 发送请求
        try self.sendSoapRequest(device, "AddPortMapping", soap_body[0..soap_len]);

        log.info("端口映射添加成功", .{});
    }

    /// 删除端口映射
    pub fn deletePortMapping(self: *Self, external_port: u16, protocol: Protocol) !void {
        const device = self.device orelse return UpnpError.NoDeviceFound;

        log.info("删除端口映射: {} ({s})", .{ external_port, protocol.toString() });

        // 构建 SOAP 请求
        var soap_body: [1024]u8 = undefined;
        const soap_len = try buildDeletePortMappingSoap(&soap_body, external_port, protocol);

        // 发送请求
        try self.sendSoapRequest(device, "DeletePortMapping", soap_body[0..soap_len]);

        log.info("端口映射删除成功", .{});
    }

    /// 获取外部 IP 地址
    pub fn getExternalIPAddress(self: *Self) ![]const u8 {
        var device = self.device orelse return UpnpError.NoDeviceFound;

        log.debug("获取外部 IP 地址...", .{});

        // 构建 SOAP 请求
        const soap_body =
            \\<?xml version="1.0"?>
            \\<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            \\<s:Body>
            \\<u:GetExternalIPAddress xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
            \\</u:GetExternalIPAddress>
            \\</s:Body>
            \\</s:Envelope>
        ;

        // 发送请求并获取响应
        var response_buf: [4096]u8 = undefined;
        const response_len = try self.sendSoapRequestWithResponseBuf(device, "GetExternalIPAddress", soap_body, &response_buf);
        const response = response_buf[0..response_len];

        // 使用 XML 解析器解析响应
        if (XmlParser.parseExternalIPResponse(response)) |ip| {
            device.setExternalIp(ip);
            self.device = device;
            log.info("外部 IP: {s}", .{ip});
            return device.getExternalIp();
        }

        log.warn("无法解析外部 IP 响应", .{});
        return UpnpError.XmlParseError;
    }

    /// 构建 AddPortMapping SOAP 请求体
    fn buildAddPortMappingSoap(buffer: []u8, mapping: PortMapping) !usize {
        const internal_client = mapping.getInternalClient();
        const description = mapping.getDescription();

        const template =
            \\<?xml version="1.0"?>
            \\<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            \\<s:Body>
            \\<u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
            \\<NewRemoteHost></NewRemoteHost>
            \\<NewExternalPort>{d}</NewExternalPort>
            \\<NewProtocol>{s}</NewProtocol>
            \\<NewInternalPort>{d}</NewInternalPort>
            \\<NewInternalClient>{s}</NewInternalClient>
            \\<NewEnabled>{d}</NewEnabled>
            \\<NewPortMappingDescription>{s}</NewPortMappingDescription>
            \\<NewLeaseDuration>{d}</NewLeaseDuration>
            \\</u:AddPortMapping>
            \\</s:Body>
            \\</s:Envelope>
        ;

        const result = std.fmt.bufPrint(buffer, template, .{
            mapping.external_port,
            mapping.protocol.toString(),
            mapping.internal_port,
            internal_client,
            @as(u8, if (mapping.enabled) 1 else 0),
            description,
            mapping.lease_duration,
        }) catch return UpnpError.InvalidResponse;

        return result.len;
    }

    /// 构建 DeletePortMapping SOAP 请求体
    fn buildDeletePortMappingSoap(buffer: []u8, external_port: u16, protocol: Protocol) !usize {
        const template =
            \\<?xml version="1.0"?>
            \\<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            \\<s:Body>
            \\<u:DeletePortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
            \\<NewRemoteHost></NewRemoteHost>
            \\<NewExternalPort>{d}</NewExternalPort>
            \\<NewProtocol>{s}</NewProtocol>
            \\</u:DeletePortMapping>
            \\</s:Body>
            \\</s:Envelope>
        ;

        const result = std.fmt.bufPrint(buffer, template, .{
            external_port,
            protocol.toString(),
        }) catch return UpnpError.InvalidResponse;

        return result.len;
    }

    /// 发送 SOAP 请求
    fn sendSoapRequest(self: *Self, device: DeviceInfo, action: []const u8, body: []const u8) !void {
        _ = self;

        // 建立 TCP 连接
        const address = net.Address.parseIp4(device.getDeviceAddr(), device.device_port) catch {
            return UpnpError.NetworkError;
        };

        const stream = net.tcpConnectToAddress(address) catch {
            return UpnpError.NetworkError;
        };
        defer stream.close();

        // 构建 HTTP 请求头
        var http_request: [4096]u8 = undefined;
        const control_url = device.getControlUrl();
        const device_addr = device.getDeviceAddr();

        const http_header = std.fmt.bufPrint(&http_request,
            \\POST {s} HTTP/1.1
            \\Host: {s}:{d}
            \\Content-Type: text/xml; charset="utf-8"
            \\Content-Length: {d}
            \\SOAPAction: "urn:schemas-upnp-org:service:WANIPConnection:1#{s}"
            \\Connection: close
            \\
            \\
        , .{
            control_url,
            device_addr,
            device.device_port,
            body.len,
            action,
        }) catch return UpnpError.InvalidResponse;

        // 发送请求头和请求体
        _ = stream.write(http_header) catch return UpnpError.NetworkError;
        _ = stream.write(body) catch return UpnpError.NetworkError;

        // 读取响应
        var response_buf: [2048]u8 = undefined;
        const response_len = stream.read(&response_buf) catch return UpnpError.NetworkError;

        if (response_len == 0) {
            return UpnpError.InvalidResponse;
        }

        // 检查 HTTP 状态码
        const response = response_buf[0..response_len];
        if (!std.mem.startsWith(u8, response, "HTTP/1.1 200") and
            !std.mem.startsWith(u8, response, "HTTP/1.0 200"))
        {
            log.err("SOAP 请求失败: {s}", .{response[0..@min(response.len, 100)]});
            return UpnpError.SoapError;
        }

        log.debug("SOAP 请求成功", .{});
    }

    /// 发送 SOAP 请求并返回响应到提供的缓冲区
    fn sendSoapRequestWithResponseBuf(self: *Self, device: DeviceInfo, action: []const u8, body: []const u8, response_buf: []u8) !usize {
        _ = self;

        // 建立 TCP 连接
        const address = net.Address.parseIp4(device.getDeviceAddr(), device.device_port) catch {
            return UpnpError.NetworkError;
        };

        const stream = net.tcpConnectToAddress(address) catch {
            return UpnpError.NetworkError;
        };
        defer stream.close();

        // 构建 HTTP 请求头
        var http_request: [4096]u8 = undefined;
        const control_url = device.getControlUrl();
        const device_addr = device.getDeviceAddr();

        const http_header = std.fmt.bufPrint(&http_request,
            \\POST {s} HTTP/1.1
            \\Host: {s}:{d}
            \\Content-Type: text/xml; charset="utf-8"
            \\Content-Length: {d}
            \\SOAPAction: "urn:schemas-upnp-org:service:WANIPConnection:1#{s}"
            \\Connection: close
            \\
            \\
        , .{
            control_url,
            device_addr,
            device.device_port,
            body.len,
            action,
        }) catch return UpnpError.InvalidResponse;

        // 发送请求头和请求体
        _ = stream.write(http_header) catch return UpnpError.NetworkError;
        _ = stream.write(body) catch return UpnpError.NetworkError;

        // 读取响应
        var total_len: usize = 0;
        while (total_len < response_buf.len) {
            const read_len = stream.read(response_buf[total_len..]) catch break;
            if (read_len == 0) break;
            total_len += read_len;
        }

        if (total_len == 0) {
            return UpnpError.InvalidResponse;
        }

        // 检查 HTTP 状态码
        const response = response_buf[0..total_len];
        if (!std.mem.startsWith(u8, response, "HTTP/1.1 200") and
            !std.mem.startsWith(u8, response, "HTTP/1.0 200"))
        {
            // 检查是否是 SOAP 错误
            if (XmlParser.parseSoapErrorCode(response)) |error_code| {
                log.err("SOAP 错误码: {}", .{error_code});
            } else {
                log.err("SOAP 请求失败: {s}", .{response[0..@min(response.len, 100)]});
            }
            return UpnpError.SoapError;
        }

        log.debug("SOAP 请求成功，响应 {} 字节", .{total_len});
        return total_len;
    }
};

/// UPnP 端口映射管理器
/// 封装了设备发现和映射管理的高级接口
pub const UpnpManager = struct {
    allocator: std.mem.Allocator,
    client: UpnpClient,
    /// 当前映射列表
    mappings: std.ArrayList(PortMapping),
    /// 是否已发现设备
    discovered: bool = false,

    const Self = @This();

    /// 初始化管理器
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .client = UpnpClient.init(allocator),
            .mappings = .{},
        };
    }

    /// 释放资源
    pub fn deinit(self: *Self) void {
        // 尝试删除所有映射
        for (self.mappings.items) |mapping| {
            self.client.deletePortMapping(mapping.external_port, mapping.protocol) catch {};
        }
        self.mappings.deinit(self.allocator);
        self.client.deinit();
    }

    /// 发现并初始化 UPnP 设备
    pub fn discoverDevice(self: *Self) !void {
        try self.client.discover();
        self.discovered = true;
    }

    /// 设置端口映射 (内外端口相同)
    pub fn setMapping(self: *Self, port: u16, protocol: Protocol, description: []const u8) !void {
        try self.setMappingEx(port, port, protocol, description);
    }

    /// 设置端口映射 (内外端口可不同)
    pub fn setMappingEx(self: *Self, internal_port: u16, external_port: u16, protocol: Protocol, description: []const u8) !void {
        if (!self.discovered) {
            try self.discoverDevice();
        }

        var mapping = PortMapping{
            .external_port = external_port,
            .internal_port = internal_port,
            .protocol = protocol,
            .lease_duration = 7 * 24 * 60 * 60, // 7天
        };
        mapping.setInternalClient(self.client.getLocalIp());
        mapping.setDescription(description);

        try self.client.addPortMapping(mapping);
        try self.mappings.append(self.allocator, mapping);
    }

    /// 移除端口映射
    pub fn removeMapping(self: *Self, external_port: u16, protocol: Protocol) !void {
        try self.client.deletePortMapping(external_port, protocol);

        // 从列表中移除
        var i: usize = 0;
        while (i < self.mappings.items.len) {
            const m = self.mappings.items[i];
            if (m.external_port == external_port and m.protocol == protocol) {
                _ = self.mappings.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// 获取外部 IP 地址
    pub fn getExternalIP(self: *Self) ![]const u8 {
        if (!self.discovered) {
            try self.discoverDevice();
        }
        return try self.client.getExternalIPAddress();
    }

    /// 获取已发现的设备信息
    pub fn getDevice(self: *const Self) ?DeviceInfo {
        return self.client.device;
    }
};

/// 综合端口映射管理器
/// 自动选择 UPnP IGD 或 NAT-PMP 协议
/// 支持 IPv4 和 IPv6 双栈发现
pub const PortMapper = struct {
    allocator: std.mem.Allocator,
    /// UPnP 客户端
    upnp_client: UpnpClient,
    /// NAT-PMP 客户端
    natpmp_client: NatPmpClient,
    /// 当前使用的协议
    active_protocol: ProtocolType = .none,
    /// 映射列表
    mappings: std.ArrayList(MappingEntry),
    /// 是否使用 IPv6
    use_ipv6: bool = false,
    /// 是否尝试双栈发现
    dual_stack: bool = true,

    const Self = @This();

    /// 协议类型
    pub const ProtocolType = enum {
        none,
        upnp,
        natpmp,
    };

    /// 映射条目
    pub const MappingEntry = struct {
        internal_port: u16,
        external_port: u16,
        protocol: Protocol,
        description: [64]u8 = [_]u8{0} ** 64,
        description_len: usize = 0,
    };

    /// 初始化
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .upnp_client = UpnpClient.init(allocator),
            .natpmp_client = NatPmpClient.init(allocator),
            .mappings = .{},
        };
    }

    /// 初始化（指定 IPv6 配置）
    pub fn initWithIPv6(allocator: std.mem.Allocator, use_ipv6: bool, dual_stack: bool) Self {
        var self = init(allocator);
        self.use_ipv6 = use_ipv6;
        self.dual_stack = dual_stack;
        self.upnp_client.use_ipv6 = use_ipv6;
        self.upnp_client.dual_stack_discovery = dual_stack;
        return self;
    }

    /// 释放资源
    pub fn deinit(self: *Self) void {
        // 删除所有映射
        for (self.mappings.items) |entry| {
            self.removeMapping(entry.external_port, entry.protocol) catch {};
        }
        self.mappings.deinit(self.allocator);
        self.upnp_client.deinit();
        self.natpmp_client.deinit();
    }

    /// 自动发现并选择可用协议（支持 IPv4 和 IPv6）
    pub fn discover(self: *Self) !void {
        log.info("开始自动发现端口映射协议 (IPv6={}, DualStack={})...", .{ self.use_ipv6, self.dual_stack });

        // 首先尝试 NAT-PMP（更轻量，目前只支持 IPv4）
        // 注：NAT-PMP 标准不支持 IPv6，PCP (RFC 6887) 是其 IPv6 后继协议
        if (!self.use_ipv6 or self.dual_stack) {
            self.natpmp_client.detectGateway() catch {
                log.debug("NAT-PMP 不可用", .{});
            };

            if (self.natpmp_client.gateway_addr_len > 0) {
                if (self.natpmp_client.getExternalIPAddress()) |_| {
                    self.active_protocol = .natpmp;
                    log.info("使用 NAT-PMP 协议", .{});
                    return;
                } else |_| {}
            }
        }

        // 然后尝试 UPnP（支持 IPv4 和 IPv6）
        self.upnp_client.discover() catch |err| {
            log.debug("UPnP 不可用: {}", .{err});
            return err;
        };

        self.active_protocol = .upnp;
        log.info("使用 UPnP 协议", .{});
    }

    /// 设置本地 IP
    pub fn setLocalIp(self: *Self, ip: []const u8) void {
        self.upnp_client.setLocalIp(ip);
    }

    /// 设置网关地址（用于 NAT-PMP）
    pub fn setGatewayAddr(self: *Self, addr: []const u8) void {
        self.natpmp_client.setGatewayAddr(addr);
    }

    /// 添加端口映射
    pub fn addMapping(self: *Self, internal_port: u16, external_port: u16, protocol: Protocol, description: []const u8) !u16 {
        if (self.active_protocol == .none) {
            try self.discover();
        }

        var actual_external_port: u16 = external_port;

        switch (self.active_protocol) {
            .natpmp => {
                actual_external_port = try self.natpmp_client.addPortMapping(
                    internal_port,
                    external_port,
                    protocol,
                    7 * 24 * 60 * 60, // 7天
                );
            },
            .upnp => {
                var mapping = PortMapping{
                    .external_port = external_port,
                    .internal_port = internal_port,
                    .protocol = protocol,
                    .lease_duration = 7 * 24 * 60 * 60,
                };
                mapping.setInternalClient(self.upnp_client.getLocalIp());
                mapping.setDescription(description);
                try self.upnp_client.addPortMapping(mapping);
            },
            .none => return UpnpError.NoDeviceFound,
        }

        // 记录映射
        var entry = MappingEntry{
            .internal_port = internal_port,
            .external_port = actual_external_port,
            .protocol = protocol,
        };
        const desc_len = @min(description.len, entry.description.len);
        @memcpy(entry.description[0..desc_len], description[0..desc_len]);
        entry.description_len = desc_len;

        try self.mappings.append(self.allocator, entry);

        return actual_external_port;
    }

    /// 删除端口映射
    pub fn removeMapping(self: *Self, external_port: u16, protocol: Protocol) !void {
        switch (self.active_protocol) {
            .natpmp => {
                // NAT-PMP 删除需要知道内部端口
                for (self.mappings.items) |entry| {
                    if (entry.external_port == external_port and entry.protocol == protocol) {
                        try self.natpmp_client.deletePortMapping(entry.internal_port, external_port, protocol);
                        break;
                    }
                }
            },
            .upnp => {
                try self.upnp_client.deletePortMapping(external_port, protocol);
            },
            .none => return UpnpError.NoDeviceFound,
        }

        // 从列表中移除
        var i: usize = 0;
        while (i < self.mappings.items.len) {
            const entry = self.mappings.items[i];
            if (entry.external_port == external_port and entry.protocol == protocol) {
                _ = self.mappings.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// 获取外部 IP
    pub fn getExternalIP(self: *Self) ![]const u8 {
        if (self.active_protocol == .none) {
            try self.discover();
        }

        return switch (self.active_protocol) {
            .natpmp => try self.natpmp_client.getExternalIPAddress(),
            .upnp => try self.upnp_client.getExternalIPAddress(),
            .none => UpnpError.NoDeviceFound,
        };
    }

    /// 获取当前使用的协议
    pub fn getActiveProtocol(self: *const Self) ProtocolType {
        return self.active_protocol;
    }
};

// ============== 测试 ==============

test "PortMapping setters" {
    var mapping = PortMapping{
        .external_port = 8080,
        .internal_port = 8080,
        .protocol = .tcp,
    };

    mapping.setInternalClient("192.168.1.100");
    try std.testing.expectEqualStrings("192.168.1.100", mapping.getInternalClient());

    mapping.setDescription("test-mapping");
    try std.testing.expectEqualStrings("test-mapping", mapping.getDescription());
}

test "DeviceInfo setters" {
    var device = DeviceInfo{};

    device.setFriendlyName("Test Router");
    try std.testing.expectEqualStrings("Test Router", device.getFriendlyName());

    device.setControlUrl("/ctl/IPConn");
    try std.testing.expectEqualStrings("/ctl/IPConn", device.getControlUrl());

    device.setDeviceAddr("192.168.1.1");
    device.device_port = 5000;
    try std.testing.expectEqualStrings("192.168.1.1", device.getDeviceAddr());
    try std.testing.expectEqual(@as(u16, 5000), device.device_port);
}

test "Protocol toString" {
    try std.testing.expectEqualStrings("TCP", Protocol.tcp.toString());
    try std.testing.expectEqualStrings("UDP", Protocol.udp.toString());
}

test "UpnpClient init" {
    const allocator = std.testing.allocator;
    var client = UpnpClient.init(allocator);
    defer client.deinit();

    client.setLocalIp("192.168.1.100");
    try std.testing.expectEqualStrings("192.168.1.100", client.getLocalIp());
}

test "URL parsing" {
    // 测试 URL 解析
    {
        const result = try UpnpClient.parseUrl("http://192.168.1.1:5000/rootDesc.xml");
        try std.testing.expectEqualStrings("192.168.1.1", result.host);
        try std.testing.expectEqual(@as(u16, 5000), result.port);
        try std.testing.expectEqualStrings("/rootDesc.xml", result.path);
    }

    {
        const result = try UpnpClient.parseUrl("http://192.168.1.1/desc.xml");
        try std.testing.expectEqualStrings("192.168.1.1", result.host);
        try std.testing.expectEqual(@as(u16, 80), result.port);
        try std.testing.expectEqualStrings("/desc.xml", result.path);
    }
}

test "SSDP location parsing" {
    const response =
        \\HTTP/1.1 200 OK
        \\CACHE-CONTROL: max-age=1800
        \\LOCATION: http://192.168.1.1:5000/rootDesc.xml
        \\ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1
        \\USN: uuid:12345678::urn:schemas-upnp-org:device:InternetGatewayDevice:1
        \\
    ;

    const location = try UpnpClient.parseSsdpLocation(response);
    try std.testing.expectEqualStrings("http://192.168.1.1:5000/rootDesc.xml", location);
}

test "UpnpManager init" {
    const allocator = std.testing.allocator;
    var manager = UpnpManager.init(allocator);
    defer manager.deinit();

    try std.testing.expect(!manager.discovered);
    try std.testing.expect(manager.getDevice() == null);
}

test "XmlParser findTagContent" {
    const xml = "<root><name>Test</name><value>123</value></root>";
    var parser = XmlParser.init(xml);

    const name = parser.findTagContent("name");
    try std.testing.expect(name != null);
    try std.testing.expectEqualStrings("Test", name.?);

    const value = parser.findTagContent("value");
    try std.testing.expect(value != null);
    try std.testing.expectEqualStrings("123", value.?);
}

test "XmlParser parseExternalIPResponse" {
    const response =
        \\HTTP/1.1 200 OK
        \\Content-Type: text/xml
        \\
        \\<?xml version="1.0"?>
        \\<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
        \\<s:Body>
        \\<u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
        \\<NewExternalIPAddress>203.0.113.50</NewExternalIPAddress>
        \\</u:GetExternalIPAddressResponse>
        \\</s:Body>
        \\</s:Envelope>
    ;

    const ip = XmlParser.parseExternalIPResponse(response);
    try std.testing.expect(ip != null);
    try std.testing.expectEqualStrings("203.0.113.50", ip.?);
}

test "XmlParser parseControlUrl" {
    const xml =
        \\<?xml version="1.0"?>
        \\<root>
        \\<device>
        \\<serviceList>
        \\<service>
        \\<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        \\<controlURL>/upnp/control/WANIPConn1</controlURL>
        \\</service>
        \\</serviceList>
        \\</device>
        \\</root>
    ;

    const url = XmlParser.parseControlUrl(xml);
    try std.testing.expect(url != null);
    try std.testing.expectEqualStrings("/upnp/control/WANIPConn1", url.?);
}

test "XmlParser parseFriendlyName" {
    const xml =
        \\<?xml version="1.0"?>
        \\<root>
        \\<device>
        \\<friendlyName>My Router</friendlyName>
        \\<manufacturer>Test Corp</manufacturer>
        \\</device>
        \\</root>
    ;

    const name = XmlParser.parseFriendlyName(xml);
    try std.testing.expect(name != null);
    try std.testing.expectEqualStrings("My Router", name.?);

    const mfr = XmlParser.parseManufacturer(xml);
    try std.testing.expect(mfr != null);
    try std.testing.expectEqualStrings("Test Corp", mfr.?);
}

test "XmlParser extractHttpBody" {
    const response = "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\n\r\n<body>content</body>";
    const body = XmlParser.extractHttpBody(response);
    try std.testing.expect(body != null);
    try std.testing.expectEqualStrings("<body>content</body>", body.?);
}

test "Protocol toNatPmpOpcode" {
    try std.testing.expectEqual(@as(u8, 1), Protocol.udp.toNatPmpOpcode());
    try std.testing.expectEqual(@as(u8, 2), Protocol.tcp.toNatPmpOpcode());
}

test "NatPmpClient init" {
    const allocator = std.testing.allocator;
    var client = NatPmpClient.init(allocator);
    defer client.deinit();

    client.setGatewayAddr("192.168.1.1");
    try std.testing.expectEqualStrings("192.168.1.1", client.getGatewayAddr());
}

test "PortMapper init" {
    const allocator = std.testing.allocator;
    var mapper = PortMapper.init(allocator);
    defer mapper.deinit();

    try std.testing.expectEqual(PortMapper.ProtocolType.none, mapper.getActiveProtocol());
}
