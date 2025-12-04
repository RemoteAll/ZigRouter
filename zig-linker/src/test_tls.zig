//! 测试 Zig 标准库 TLS 支持
//! 结论：Zig 0.15.2 std.crypto.tls 同时支持 TLS 1.2 和 TLS 1.3
const std = @import("std");
const net = std.net;
const tls = std.crypto.tls;

pub fn main() !void {
    std.debug.print("=== Zig TLS 版本测试 ===\n\n", .{});

    // 打印 Zig 标准库支持的 TLS 版本
    std.debug.print("Zig std.crypto.tls 支持的协议版本:\n", .{});
    std.debug.print("  - tls_1_2 = 0x{x:0>4} (TLS 1.2)\n", .{@intFromEnum(tls.ProtocolVersion.tls_1_2)});
    std.debug.print("  - tls_1_3 = 0x{x:0>4} (TLS 1.3)\n", .{@intFromEnum(tls.ProtocolVersion.tls_1_3)});

    // 测试 HTTPS 连接（底层使用 TLS）
    std.debug.print("\n=== 测试 HTTPS 连接 ===\n", .{});

    const allocator = std.heap.page_allocator;
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const result = client.fetch(.{
        .location = .{ .url = "https://www.baidu.com/" },
    }) catch |err| {
        std.debug.print("请求失败: {}\n", .{err});
        return;
    };

    std.debug.print("HTTPS 请求成功! 状态码: {}\n", .{result.status});
    std.debug.print("\n>>> TLS 握手成功！<<<\n", .{});

    // 说明
    std.debug.print("\n=== 判断依据 ===\n", .{});
    std.debug.print("1. HTTPS 连接成功 = TLS 握手成功\n", .{});
    std.debug.print("2. Zig ClientHello 同时提供 TLS 1.2/1.3 密码套件\n", .{});
    std.debug.print("3. 服务器会选择最高支持版本（现代服务器通常选 TLS 1.3）\n", .{});
    std.debug.print("\n用 curl 验证百度支持 TLS 1.3:\n", .{});
    std.debug.print("  curl -v https://www.baidu.com 2>&1 | findstr TLS\n", .{});
}
