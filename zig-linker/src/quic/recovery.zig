//! QUIC 丢包检测与拥塞控制
//! 实现 RFC 9002

const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types.zig");
const PacketNumberSpace = types.PacketNumberSpace;

/// 拥塞控制算法
pub const CongestionAlgorithm = enum {
    /// 新 Reno（默认）
    new_reno,
    /// Cubic
    cubic,
    /// BBR
    bbr,
};

/// 已发送包信息
pub const SentPacket = struct {
    /// 包号
    packet_number: u64,
    /// 包号空间
    space: PacketNumberSpace,
    /// 发送时间（纳秒）
    time_sent: i128,
    /// 包大小（字节）
    size: usize,
    /// 是否触发 ACK
    ack_eliciting: bool,
    /// 是否包含 CRYPTO 帧
    in_flight: bool,
    /// 是否已确认
    acked: bool = false,
    /// 是否已标记为丢失
    lost: bool = false,
};

/// RTT 测量
pub const RttEstimator = struct {
    /// 最小 RTT（纳秒）
    min_rtt: u64 = std.math.maxInt(u64),
    /// 平滑 RTT（纳秒）
    smoothed_rtt: u64 = 333_000_000, // 初始 333ms
    /// RTT 变化值
    rttvar: u64 = 166_500_000, // 初始 smoothed_rtt / 2
    /// 最新 RTT
    latest_rtt: u64 = 0,
    /// 是否有 RTT 样本
    has_sample: bool = false,

    const INITIAL_RTT: u64 = 333_000_000; // 333ms

    /// 更新 RTT 估计
    pub fn update(self: *RttEstimator, rtt_sample: u64, ack_delay: u64) void {
        self.latest_rtt = rtt_sample;

        if (!self.has_sample) {
            // 第一个样本
            self.min_rtt = rtt_sample;
            self.smoothed_rtt = rtt_sample;
            self.rttvar = rtt_sample / 2;
            self.has_sample = true;
            return;
        }

        // 更新最小 RTT
        if (rtt_sample < self.min_rtt) {
            self.min_rtt = rtt_sample;
        }

        // 调整 ACK 延迟
        const adjusted_rtt = if (rtt_sample > self.min_rtt + ack_delay)
            rtt_sample - ack_delay
        else
            rtt_sample;

        // 更新 smoothed_rtt 和 rttvar
        const abs_diff = if (self.smoothed_rtt > adjusted_rtt)
            self.smoothed_rtt - adjusted_rtt
        else
            adjusted_rtt - self.smoothed_rtt;

        self.rttvar = (3 * self.rttvar + abs_diff) / 4;
        self.smoothed_rtt = (7 * self.smoothed_rtt + adjusted_rtt) / 8;
    }

    /// 获取 PTO（探测超时）
    pub fn getPto(self: *const RttEstimator, max_ack_delay: u64) u64 {
        return self.smoothed_rtt + @max(4 * self.rttvar, 1_000_000) + max_ack_delay;
    }
};

/// 拥塞控制器
pub const CongestionController = struct {
    /// 算法
    algorithm: CongestionAlgorithm = .new_reno,

    /// 拥塞窗口（字节）
    cwnd: u64 = INITIAL_WINDOW,
    /// 慢启动阈值
    ssthresh: u64 = std.math.maxInt(u64),
    /// 在途字节数
    bytes_in_flight: u64 = 0,

    /// 拥塞恢复开始时间
    congestion_recovery_start_time: i128 = 0,

    /// ECN 计数
    ecn_ce_count: u64 = 0,

    const INITIAL_WINDOW: u64 = 14720; // 约 10 个包
    const MINIMUM_WINDOW: u64 = 2 * 1200; // 2 个最小 MTU
    const LOSS_REDUCTION_FACTOR: u64 = 2; // New Reno 减半

    /// 收到 ACK 时更新
    pub fn onAck(self: *CongestionController, acked_bytes: u64, now: i128) void {
        self.bytes_in_flight = if (self.bytes_in_flight > acked_bytes)
            self.bytes_in_flight - acked_bytes
        else
            0;

        // 检查是否在拥塞恢复期
        if (self.isInCongestionRecovery(now)) {
            return;
        }

        if (self.cwnd < self.ssthresh) {
            // 慢启动
            self.cwnd += acked_bytes;
        } else {
            // 拥塞避免
            self.cwnd += (1200 * acked_bytes) / self.cwnd;
        }
    }

    /// 检测到丢包时更新
    pub fn onPacketLoss(self: *CongestionController, lost_bytes: u64, now: i128) void {
        self.bytes_in_flight = if (self.bytes_in_flight > lost_bytes)
            self.bytes_in_flight - lost_bytes
        else
            0;

        // 进入拥塞恢复
        if (!self.isInCongestionRecovery(now)) {
            self.congestion_recovery_start_time = now;
            self.ssthresh = self.cwnd / LOSS_REDUCTION_FACTOR;
            self.cwnd = @max(self.ssthresh, MINIMUM_WINDOW);
        }
    }

    /// 发送包时更新
    pub fn onPacketSent(self: *CongestionController, bytes: u64) void {
        self.bytes_in_flight += bytes;
    }

    /// 是否可以发送
    pub fn canSend(self: *const CongestionController) bool {
        return self.bytes_in_flight < self.cwnd;
    }

    /// 可发送字节数
    pub fn availableWindow(self: *const CongestionController) u64 {
        if (self.cwnd > self.bytes_in_flight) {
            return self.cwnd - self.bytes_in_flight;
        }
        return 0;
    }

    fn isInCongestionRecovery(self: *const CongestionController, now: i128) bool {
        return now < self.congestion_recovery_start_time + 1_000_000_000; // 1 秒恢复期
    }

    /// 处理 ECN 拥塞事件
    pub fn onEcnCongestion(self: *CongestionController, ce_count: u64, now: i128) void {
        if (ce_count > self.ecn_ce_count) {
            self.ecn_ce_count = ce_count;
            if (!self.isInCongestionRecovery(now)) {
                self.congestion_recovery_start_time = now;
                self.ssthresh = self.cwnd / LOSS_REDUCTION_FACTOR;
                self.cwnd = @max(self.ssthresh, MINIMUM_WINDOW);
            }
        }
    }
};

/// 丢包检测器
pub const LossDetector = struct {
    allocator: Allocator,

    /// RTT 估计器
    rtt: RttEstimator = .{},
    /// 拥塞控制器
    cc: CongestionController = .{},

    /// 已发送包（按包号空间）
    sent_packets: [3]std.ArrayListUnmanaged(SentPacket) = .{ .{}, .{}, .{} },

    /// 最大已确认包号（按包号空间）
    largest_acked_packet: [3]?u64 = .{ null, null, null },
    /// 丢包时间（按包号空间）
    loss_time: [3]?i128 = .{ null, null, null },
    /// 最后发送 ack-eliciting 包时间（按包号空间）
    time_of_last_ack_eliciting_packet: [3]?i128 = .{ null, null, null },

    /// PTO 计数
    pto_count: u32 = 0,
    /// 最大 ACK 延迟
    max_ack_delay: u64 = 25_000_000, // 25ms

    /// 丢包阈值（包数）
    const K_PACKET_THRESHOLD: u64 = 3;
    /// 丢包阈值（时间因子）
    const K_TIME_THRESHOLD: u64 = 9; // 9/8

    pub fn init(allocator: Allocator) LossDetector {
        return .{
            .allocator = allocator,
            .sent_packets = .{
                .{},
                .{},
                .{},
            },
        };
    }

    pub fn deinit(self: *LossDetector) void {
        for (&self.sent_packets) |*list| {
            list.deinit(self.allocator);
        }
    }

    /// 记录发送的包
    pub fn onPacketSent(self: *LossDetector, pkt: SentPacket) !void {
        const space = @intFromEnum(pkt.space);
        try self.sent_packets[space].append(self.allocator, pkt);

        if (pkt.in_flight) {
            self.cc.onPacketSent(pkt.size);
        }

        if (pkt.ack_eliciting) {
            self.time_of_last_ack_eliciting_packet[space] = pkt.time_sent;
        }
    }

    /// 处理 ACK 帧
    pub fn onAckReceived(
        self: *LossDetector,
        space: PacketNumberSpace,
        largest_acked: u64,
        ack_delay: u64,
        ack_ranges: []const struct { start: u64, end: u64 },
        now: i128,
    ) ![]SentPacket {
        const space_idx = @intFromEnum(space);

        // 更新最大已确认包号
        if (self.largest_acked_packet[space_idx] == null or largest_acked > self.largest_acked_packet[space_idx].?) {
            self.largest_acked_packet[space_idx] = largest_acked;
        }

        // 标记已确认的包
        var newly_acked_bytes: u64 = 0;
        var largest_newly_acked: ?*SentPacket = null;

        for (self.sent_packets[space_idx].items) |*pkt| {
            if (!pkt.acked and !pkt.lost) {
                // 检查包号是否在 ACK 范围内
                for (ack_ranges) |range| {
                    if (pkt.packet_number >= range.start and pkt.packet_number <= range.end) {
                        pkt.acked = true;
                        if (pkt.in_flight) {
                            newly_acked_bytes += pkt.size;
                        }
                        if (largest_newly_acked == null or pkt.packet_number > largest_newly_acked.?.packet_number) {
                            largest_newly_acked = pkt;
                        }
                        break;
                    }
                }
            }
        }

        // 更新 RTT
        if (largest_newly_acked) |pkt| {
            const rtt_sample: u64 = @intCast(now - pkt.time_sent);
            self.rtt.update(rtt_sample, ack_delay);
        }

        // 更新拥塞控制
        self.cc.onAck(newly_acked_bytes, now);

        // 检测丢包
        const lost_packets = try self.detectLostPackets(space, now);

        // 重置 PTO 计数
        self.pto_count = 0;

        return lost_packets;
    }

    /// 检测丢失的包
    fn detectLostPackets(self: *LossDetector, space: PacketNumberSpace, now: i128) ![]SentPacket {
        const space_idx = @intFromEnum(space);
        const largest_acked = self.largest_acked_packet[space_idx] orelse return &[_]SentPacket{};

        // 计算丢包时间阈值
        const loss_delay = @max(
            (self.rtt.latest_rtt * K_TIME_THRESHOLD) / 8,
            (self.rtt.smoothed_rtt * K_TIME_THRESHOLD) / 8,
        );
        const lost_send_time = now - @as(i128, @intCast(loss_delay));

        var lost_packets: std.ArrayListUnmanaged(SentPacket) = .{};
        var lost_bytes: u64 = 0;

        for (self.sent_packets[space_idx].items) |*pkt| {
            if (pkt.acked or pkt.lost) continue;

            // 包号阈值检测
            if (pkt.packet_number + K_PACKET_THRESHOLD <= largest_acked) {
                pkt.lost = true;
                if (pkt.in_flight) {
                    lost_bytes += pkt.size;
                }
                try lost_packets.append(self.allocator, pkt.*);
                continue;
            }

            // 时间阈值检测
            if (pkt.time_sent <= lost_send_time) {
                pkt.lost = true;
                if (pkt.in_flight) {
                    lost_bytes += pkt.size;
                }
                try lost_packets.append(self.allocator, pkt.*);
            }
        }

        // 更新拥塞控制
        if (lost_bytes > 0) {
            self.cc.onPacketLoss(lost_bytes, now);
        }

        return lost_packets.toOwnedSlice(self.allocator);
    }

    /// 获取丢包检测超时时间
    pub fn getLossDetectionTimeout(self: *const LossDetector) ?i128 {
        // 检查是否有丢包时间设置
        var earliest_loss_time: ?i128 = null;
        for (self.loss_time) |lt| {
            if (lt) |t| {
                if (earliest_loss_time == null or t < earliest_loss_time.?) {
                    earliest_loss_time = t;
                }
            }
        }
        if (earliest_loss_time) |t| return t;

        // 检查是否有未确认的 ack-eliciting 包
        var has_ack_eliciting = false;
        var last_time: ?i128 = null;

        for (0..3) |i| {
            if (self.time_of_last_ack_eliciting_packet[i]) |t| {
                has_ack_eliciting = true;
                if (last_time == null or t > last_time.?) {
                    last_time = t;
                }
            }
        }

        if (!has_ack_eliciting) return null;

        // 计算 PTO
        var pto = self.rtt.getPto(self.max_ack_delay);
        pto = pto << self.pto_count;

        return last_time.? + @as(i128, @intCast(pto));
    }

    /// PTO 超时处理
    pub fn onPtoTimeout(self: *LossDetector) void {
        self.pto_count += 1;
    }
};

// ============ 单元测试 ============

test "rtt estimator" {
    const testing = std.testing;

    var rtt = RttEstimator{};

    // 第一个样本
    rtt.update(100_000_000, 0); // 100ms
    try testing.expectEqual(@as(u64, 100_000_000), rtt.min_rtt);
    try testing.expectEqual(@as(u64, 100_000_000), rtt.smoothed_rtt);

    // 更多样本
    rtt.update(120_000_000, 10_000_000); // 120ms, 10ms ack_delay
    try testing.expectEqual(@as(u64, 100_000_000), rtt.min_rtt);
    try testing.expect(rtt.smoothed_rtt > 100_000_000);
}

test "congestion controller" {
    var cc = CongestionController{};

    try std.testing.expect(cc.canSend());
    try std.testing.expect(cc.availableWindow() > 0);

    // 发送包
    cc.onPacketSent(1200);
    try std.testing.expectEqual(@as(u64, 1200), cc.bytes_in_flight);

    // 确认包
    const now = std.time.nanoTimestamp();
    cc.onAck(1200, now);
    try std.testing.expectEqual(@as(u64, 0), cc.bytes_in_flight);
}

test "loss detector init" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var detector = LossDetector.init(allocator);
    defer detector.deinit();

    // 记录发送包
    try detector.onPacketSent(.{
        .packet_number = 0,
        .space = .initial,
        .time_sent = std.time.nanoTimestamp(),
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });

    try testing.expectEqual(@as(usize, 1), detector.sent_packets[0].items.len);
}
