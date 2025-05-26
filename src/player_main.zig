const std = @import("std");
const potato = @import("potato.zig");

pub fn main() !void {
    const allocator = std.heap.smp_allocator;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 5) {
        std.log.err("usage: player <ring master IP> <ring master port> <listen IP> <listen port>", .{});
        return;
    }

    const ring_master_port = try std.fmt.parseInt(u16, args[2], 10);
    const ring_master_addr = try std.net.Address.parseIp4(args[1], ring_master_port);
    const player_port = try std.fmt.parseInt(u16, args[4], 10);
    const player_addr = try std.net.Address.parseIp4(args[3], player_port);

    var player = try potato.Player.init(allocator);
    defer player.deinit();

    try player.handshake(ring_master_addr, player_addr);
    defer player.shutdown();

    var rng = std.Random.DefaultPrng.init(seed: {
        var s: u64 = undefined;
        try std.posix.getrandom(std.mem.asBytes(&s));
        break :seed s;
    });
    try player.play(rng.random());
}
