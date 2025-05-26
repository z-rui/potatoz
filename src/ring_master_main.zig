const std = @import("std");
const potato = @import("potato.zig");

pub fn main() !void {
    const allocator = std.heap.smp_allocator;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 5) {
        std.log.err("usage: ring_master <listen IP> <listen port> <n> <hops>", .{});
        return;
    }

    const ring_master_port = try std.fmt.parseInt(u16, args[2], 10);
    const ring_master_addr = try std.net.Address.parseIp4(args[1], ring_master_port);
    const n = try std.fmt.parseInt(usize, args[3], 10);
    const hops = try std.fmt.parseInt(u32, args[4], 10);

    if (n < 1) {
        std.log.err("must have at least 1 player", .{});
        return;
    }

    if (hops < 1) {
        std.log.err("must have at least 1 hop", .{});
        return;
    }

    var ring_master = try potato.RingMaster.init(allocator, n);
    defer ring_master.deinit();

    try ring_master.handshake(ring_master_addr);
    defer ring_master.shutdown();

    var rng = std.Random.DefaultPrng.init(seed: {
        var s: u64 = undefined;
        try std.posix.getrandom(std.mem.asBytes(&s));
        break :seed s;
    });
    try ring_master.play(rng.random(), hops);
}
