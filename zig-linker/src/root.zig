//! Zig Linker - NAT 穿透打洞库
//! 参考 C# linker 项目实现的 7 种打洞方式
//!
//! 支持的打洞方式：
//! 1. UDP - UDP 直接打洞
//! 2. UdpP2PNAT - UDP 同时打开
//! 3. TcpP2PNAT - TCP 同时打开
//! 4. TcpNutssb - TCP 低TTL打洞
//! 5. UdpPortMap - UDP 端口映射
//! 6. TcpPortMap - TCP 端口映射
//! 7. MsQuic - QUIC 协议 (暂未实现)
//!
//! 辅助功能：
//! - UPnP IGD 自动端口映射

const std = @import("std");

// 导出所有公共模块
pub const log = @import("tunnel/log.zig");
pub const types = @import("tunnel/types.zig");
pub const net_utils = @import("tunnel/net_utils.zig");
pub const stun = @import("tunnel/stun.zig");
pub const protocol = @import("tunnel/protocol.zig");
pub const transport = @import("tunnel/transport.zig");
pub const server = @import("tunnel/server.zig");
pub const client = @import("tunnel/client.zig");
pub const upnp = @import("tunnel/upnp.zig");

/// 库版本
pub const version = "0.1.0";

/// 打印带缓冲的输出（用于测试）
pub fn bufferedPrint() !void {
    std.debug.print("Zig Linker v{s} - NAT Traversal Library\n", .{version});
    std.debug.print("Supported hole punching methods:\n", .{});
    std.debug.print("  1. UDP (Pure UDP hole punching)\n", .{});
    std.debug.print("  2. UdpP2PNAT (UDP simultaneous open)\n", .{});
    std.debug.print("  3. TcpP2PNAT (TCP simultaneous open)\n", .{});
    std.debug.print("  4. TcpNutssb (TCP with low TTL)\n", .{});
    std.debug.print("  5. UdpPortMap (UDP port mapping)\n", .{});
    std.debug.print("  6. TcpPortMap (TCP port mapping)\n", .{});
    std.debug.print("  7. MsQuic (QUIC protocol - not implemented)\n", .{});
    std.debug.print("\nAuxiliary features:\n", .{});
    std.debug.print("  - UPnP IGD (Auto port mapping)\n", .{});
}

test "basic functionality" {
    try bufferedPrint();
}
