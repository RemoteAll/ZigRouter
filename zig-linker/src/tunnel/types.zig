//! 打洞相关的类型定义
//! 参考 C# linker 项目的类型结构

const std = @import("std");
const net = std.net;

/// NAT 类型枚举
/// 参考 RFC 3489 定义
pub const NatType = enum {
    /// 未知类型
    unknown,
    /// 服务器不支持测试 NAT 类型
    unsupported_server,
    /// UDP 被完全阻止
    udp_blocked,
    /// 无 NAT，公网 IP，无防火墙
    open_internet,
    /// 无 NAT，公网 IP，但有对称 UDP 防火墙
    symmetric_udp_firewall,
    /// 全锥型 NAT (Full Cone)
    /// 所有来自相同内部 IP:Port 的请求映射到相同的外部 IP:Port
    /// 任何外部主机都可以向内部主机发送数据
    full_cone,
    /// 受限锥型 NAT (Restricted Cone)
    /// 只有内部主机曾经发送过数据的 IP 才能向内部主机发送数据
    restricted_cone,
    /// 端口受限锥型 NAT (Port Restricted Cone)
    /// 只有内部主机曾经发送过数据的 IP:Port 才能向内部主机发送数据
    port_restricted_cone,
    /// 对称型 NAT (Symmetric)
    /// 每个不同的目的 IP:Port 都会产生不同的映射
    symmetric,

    /// 获取 NAT 类型的描述
    pub fn description(self: NatType) []const u8 {
        return switch (self) {
            .unknown => "未知",
            .unsupported_server => "服务器不支持",
            .udp_blocked => "UDP被阻止",
            .open_internet => "公网(无NAT)",
            .symmetric_udp_firewall => "对称UDP防火墙",
            .full_cone => "全锥型NAT",
            .restricted_cone => "受限锥型NAT",
            .port_restricted_cone => "端口受限锥型NAT",
            .symmetric => "对称型NAT",
        };
    }

    /// 判断是否可以进行 P2P 打洞
    pub fn canP2P(self: NatType, other: NatType) bool {
        // 对称型 NAT 之间无法打洞
        if (self == .symmetric and other == .symmetric) {
            return false;
        }
        // 对称型 NAT 与端口受限锥型 NAT 也很难打洞
        if ((self == .symmetric and other == .port_restricted_cone) or
            (self == .port_restricted_cone and other == .symmetric))
        {
            return false;
        }
        // UDP 被阻止的情况
        if (self == .udp_blocked or other == .udp_blocked) {
            return false;
        }
        return true;
    }
};

/// 隧道协议类型
pub const TunnelProtocolType = enum {
    tcp,
    udp,
    quic,

    pub fn toString(self: TunnelProtocolType) []const u8 {
        return switch (self) {
            .tcp => "TCP",
            .udp => "UDP",
            .quic => "QUIC",
        };
    }
};

/// 打洞传输方式
pub const TransportType = enum {
    /// UDP 直接打洞
    udp,
    /// UDP 同时打开 (UDP Simultaneous Open)
    udp_p2p_nat,
    /// TCP 同时打开 (TCP Simultaneous Open)
    tcp_p2p_nat,
    /// TCP 低 TTL 打洞
    tcp_nutssb,
    /// UDP 端口映射
    udp_port_map,
    /// TCP 端口映射
    tcp_port_map,
    /// QUIC 协议
    msquic,

    pub fn name(self: TransportType) []const u8 {
        return switch (self) {
            .udp => "Udp",
            .udp_p2p_nat => "UdpP2PNAT",
            .tcp_p2p_nat => "TcpP2PNAT",
            .tcp_nutssb => "TcpNutssb",
            .udp_port_map => "UdpPortMap",
            .tcp_port_map => "TcpPortMap",
            .msquic => "MsQuic",
        };
    }

    pub fn label(self: TransportType) []const u8 {
        return switch (self) {
            .udp => "UDP、非常纯",
            .udp_p2p_nat => "UDP、同时打开",
            .tcp_p2p_nat => "TCP、同时打开",
            .tcp_nutssb => "TCP、低TTL",
            .udp_port_map => "UDP、端口映射",
            .tcp_port_map => "TCP、端口映射",
            .msquic => "MsQuic，win10+、linux",
        };
    }

    /// 获取传输方式描述
    pub fn description(self: TransportType) []const u8 {
        return self.label();
    }

    pub fn protocolType(self: TransportType) TunnelProtocolType {
        return switch (self) {
            .udp, .udp_p2p_nat, .udp_port_map => .udp,
            .tcp_p2p_nat, .tcp_nutssb, .tcp_port_map => .tcp,
            .msquic => .quic,
        };
    }

    pub fn defaultOrder(self: TransportType) u8 {
        return switch (self) {
            .udp_port_map => 1,
            .tcp_port_map => 2,
            .udp => 3,
            .udp_p2p_nat => 3,
            .tcp_p2p_nat => 4,
            .tcp_nutssb => 5,
            .msquic => 255,
        };
    }
};

/// 打洞方向
pub const TunnelDirection = enum {
    /// 正向打洞：主动发起方
    forward,
    /// 反向打洞：被动接收方
    reverse,

    pub fn toString(self: TunnelDirection) []const u8 {
        return switch (self) {
            .forward => "正向",
            .reverse => "反向",
        };
    }

    pub fn description(self: TunnelDirection) []const u8 {
        return self.toString();
    }
};

/// 隧道类型
pub const TunnelType = enum {
    /// P2P 直连
    p2p,
    /// 中继转发
    relay,

    pub fn toString(self: TunnelType) []const u8 {
        return switch (self) {
            .p2p => "P2P",
            .relay => "中继",
        };
    }
};

/// 隧道模式
pub const TunnelMode = enum {
    /// 客户端模式
    client,
    /// 服务端模式
    server,

    pub fn toString(self: TunnelMode) []const u8 {
        return switch (self) {
            .client => "客户端",
            .server => "服务端",
        };
    }
};

/// 端点地址信息
pub const EndpointInfo = struct {
    /// 本地地址
    local: net.Address,
    /// 外网地址（经 NAT 映射后）
    remote: ?net.Address = null,
    /// 局域网 IP 列表
    local_ips: []const net.Address = &.{},
    /// 外网层级（经过多少层 NAT）
    route_level: u8 = 1,
    /// 机器 ID
    machine_id: []const u8 = "",
    /// 机器名称
    machine_name: []const u8 = "",
    /// 固定端口映射（外网）
    port_map_wan: u16 = 0,
    /// 固定端口映射（内网）
    port_map_lan: u16 = 0,
    /// NAT 类型
    nat_type: NatType = .unknown,

    /// 格式化输出端点信息
    pub fn format(
        self: EndpointInfo,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("EndpointInfo{{ machine_id={s}, nat={s}, local={any}, remote={any} }}", .{
            if (self.machine_id.len > 0) self.machine_id else "(unknown)",
            self.nat_type.description(),
            self.local,
            self.remote,
        });
    }
};

/// 打洞传输信息
pub const TunnelTransportInfo = struct {
    /// 本方信息
    local: EndpointInfo,
    /// 对方信息
    remote: EndpointInfo,
    /// 事务 ID
    transaction_id: []const u8 = "",
    /// 传输协议类型
    transport_type: TunnelProtocolType = .udp,
    /// 传输方式名称
    transport_name: TransportType = .udp,
    /// 打洞方向
    direction: TunnelDirection = .forward,
    /// 是否需要 SSL
    ssl: bool = false,
    /// 缓冲区大小级别 (2^n KB)
    buffer_size: u8 = 3,
    /// 流 ID
    flow_id: u32 = 0,
    /// 标签
    transaction_tag: []const u8 = "",
    /// 目标端点列表（用于尝试连接）
    remote_endpoints: []const net.Address = &.{},

    /// 格式化输出传输信息
    pub fn format(
        self: TunnelTransportInfo,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("TunnelTransportInfo{{ {s} {s}, local={any}, remote={any}, dir={s} }}", .{
            self.transport_name.name(),
            self.transport_type.toString(),
            self.local,
            self.remote,
            self.direction.toString(),
        });
    }
};

/// 隧道连接信息
pub const TunnelConnectionInfo = struct {
    /// 远程端点地址
    remote_endpoint: net.Address,
    /// 事务 ID
    transaction_id: []const u8 = "",
    /// 事务标签
    transaction_tag: []const u8 = "",
    /// 远程机器 ID
    remote_machine_id: []const u8 = "",
    /// 远程机器名称
    remote_machine_name: []const u8 = "",
    /// 传输方式名称
    transport_name: TransportType = .udp,
    /// 打洞方向
    direction: TunnelDirection = .forward,
    /// 协议类型
    protocol_type: TunnelProtocolType = .udp,
    /// 隧道类型
    tunnel_type: TunnelType = .p2p,
    /// 隧道模式
    mode: TunnelMode = .client,
    /// 是否使用 SSL
    ssl: bool = false,
    /// 连接时间戳
    connected_at: i64 = 0,
    /// Hello 握手是否已完成（用于同步打洞成功状态）
    hello_completed: bool = false,

    /// 格式化输出连接信息
    pub fn format(
        self: TunnelConnectionInfo,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("Connection{{ {s}->{s}, {s} {s}, {s}, {any} }}", .{
            if (self.remote_machine_id.len > 0) self.remote_machine_id else "(unknown)",
            if (self.remote_machine_name.len > 0) self.remote_machine_name else "(unknown)",
            self.transport_name.name(),
            self.tunnel_type.toString(),
            self.mode.toString(),
            self.remote_endpoint,
        });
    }
};

/// STUN 消息类型
pub const StunMessageType = enum(u16) {
    binding_request = 0x0001,
    binding_response = 0x0101,
    binding_error_response = 0x0111,
    shared_secret_request = 0x0002,
    shared_secret_response = 0x0102,
    shared_secret_error_response = 0x0112,
    _,
};

/// STUN 属性类型
pub const StunAttributeType = enum(u16) {
    mapped_address = 0x0001,
    response_address = 0x0002,
    change_request = 0x0003,
    source_address = 0x0004,
    changed_address = 0x0005,
    username = 0x0006,
    password = 0x0007,
    message_integrity = 0x0008,
    error_code = 0x0009,
    unknown_attributes = 0x000A,
    reflected_from = 0x000B,
    // RFC 5389 扩展
    xor_mapped_address = 0x0020,
    software = 0x8022,
    alternate_server = 0x8023,
    fingerprint = 0x8028,
    _,
};

test "NatType descriptions" {
    try std.testing.expectEqualStrings("全锥型NAT", NatType.full_cone.description());
    try std.testing.expectEqualStrings("对称型NAT", NatType.symmetric.description());
}

test "NatType P2P capability" {
    // 全锥型之间可以打洞
    try std.testing.expect(NatType.full_cone.canP2P(.full_cone));
    // 对称型之间不能打洞
    try std.testing.expect(!NatType.symmetric.canP2P(.symmetric));
}

test "TransportType properties" {
    try std.testing.expectEqualStrings("UDP", TransportType.udp.name());
    try std.testing.expect(TransportType.udp.protocolType() == .udp);
    try std.testing.expect(TransportType.tcp_p2p_nat.protocolType() == .tcp);
}
