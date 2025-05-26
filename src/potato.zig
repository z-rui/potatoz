const std = @import("std");
const net = std.net;
const posix = std.posix;
const log = std.log;
const testing = std.testing;
const assert = std.debug.assert;

const trace_sentinel = std.math.maxInt(u32);

fn sendAddress(peer: net.Stream, addr: net.Address) !void {
    var buf: [6]u8 = undefined;
    @memcpy(buf[0..4], std.mem.asBytes(&addr.in.sa.addr));
    std.mem.writeInt(u16, buf[4..], addr.getPort(), .big);
    try peer.writeAll(&buf);
}

fn recvAddress(peer: net.Stream) !net.Address {
    var buf: [6]u8 = undefined;
    const len = try peer.readAll(&buf);
    assert(len == 6);
    return .initIp4(buf[0..4].*, std.mem.readInt(u16, buf[4..], .big));
}

fn pollOne(fds: []posix.pollfd) !usize {
    const n = try posix.poll(fds, -1);
    var idx: ?usize = null;
    assert(n > 0);

    for (fds, 0..) |fd, i| {
        if (fd.revents & (posix.POLL.ERR | posix.POLL.HUP | posix.POLL.NVAL) != 0)
            return error.RemoteError;
        if (fd.revents != 0) {
            if (idx) |_| return error.MultipleEvents;
            idx = i;
        }
    }
    return idx orelse unreachable;
}

const Server = struct {
    server: net.Server,
    conn: anyerror!net.Server.Connection,
    thread: std.Thread,

    fn listen(self: *@This(), addr: net.Address) !void {
        self.server = try addr.listen(.{});
        log.debug("listening on {}", .{self.server.listen_address});
        self.thread = try std.Thread.spawn(.{}, threadEntry, .{self});
    }

    fn getListenAddress(self: *const @This()) net.Address {
        return self.server.listen_address;
    }

    fn threadEntry(self: *@This()) void {
        self.conn = self.server.accept();
    }

    fn accept(self: *const @This()) !net.Server.Connection {
        self.thread.join();
        return self.conn;
    }

    fn deinit(self: *@This()) void {
        self.server.deinit();
    }
};

fn createLoopbackPair() !struct { net.Stream, net.Stream } {
    const addr = net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    var server: Server = undefined;
    try server.listen(addr);
    defer server.deinit();
    const stream1 = try net.tcpConnectToAddress(server.getListenAddress());
    const stream2 = (try server.accept()).stream;
    return .{ stream1, stream2 };
}

test "sendU32" {
    const peer1, const peer2 = try createLoopbackPair();
    defer peer1.close();
    defer peer2.close();
    try peer1.writer().writeInt(u32, 0xdeadbeef, .big);
    try testing.expectEqual(0xdeadbeef, try peer2.reader().readInt(u32, .big));
}

test "sendAddress" {
    const peer1, const peer2 = try createLoopbackPair();
    defer peer1.close();
    defer peer2.close();
    const addr = net.Address.initIp4(.{ 127, 0, 0, 1 }, 8086);
    try sendAddress(peer1, addr);
    const received_addr = try recvAddress(peer2);
    try testing.expectEqual(addr.in, received_addr.in);
}

pub const RingMaster = struct {
    allocator: std.mem.Allocator,
    peers: []net.Stream,

    pub fn init(allocator: std.mem.Allocator, n: usize) !@This() {
        assert(n > 0);
        const peers = try allocator.alloc(net.Stream, n);
        errdefer allocator.free(peers);
        log.info("Potato Ringmaster", .{});
        log.info("Players = {}", .{n});
        return .{
            .allocator = allocator,
            .peers = peers,
        };
    }

    pub fn handshake(self: *@This(), listen_addr: net.Address) !void {
        log.debug("handshake start", .{});
        var server = try listen_addr.listen(.{});
        defer server.deinit();
        log.debug("listening on {}", .{server.listen_address});

        const n = self.peers.len;
        var peer_addrs = try self.allocator.alloc(net.Address, n);
        defer self.allocator.free(peer_addrs);
        for (0..n) |i| {
            errdefer {
                for (self.peers[0..i]) |peer| {
                    peer.close();
                }
            }
            const conn = try server.accept();
            const remote_listen_port = try conn.stream.reader().readInt(u16, .big);
            log.info("Player {} is ready to play", .{i});
            log.debug(
                "player {} is from {}, listening on {}",
                .{ i, conn.address, remote_listen_port },
            );
            self.peers[i] = conn.stream;
            peer_addrs[i] = conn.address;
            peer_addrs[i].setPort(remote_listen_port);
        }
        log.debug("send init info to peers", .{});
        for (self.peers, 0..) |peer, i| {
            // Let peers[i] connect to peers[i+1], to form a ring.
            try peer.writer().writeInt(u32, @intCast(i), .big);
            try sendAddress(peer, peer_addrs[(i + 1) % n]);
        }
        log.debug("handshake done", .{});
    }

    pub fn play(self: *@This(), rng: std.Random, hops: u32) !void {
        log.info("Hops = {}", .{hops});
        const n = self.peers.len;
        const fds = try self.allocator.alloc(posix.pollfd, n);
        defer self.allocator.free(fds);
        for (self.peers, fds) |stream, *pfd| {
            pfd.fd = stream.handle;
            pfd.events = posix.POLL.IN;
        }
        const trace_buf = try self.allocator.alloc(u32, hops);
        defer self.allocator.free(trace_buf);

        const chosen_one = rng.uintLessThan(usize, n);
        log.info("Ready to start the game, sending potato to player {}", .{chosen_one});
        try self.peers[chosen_one].writer().writeInt(u32, hops, .big);
        try self.peers[chosen_one].writer().writeInt(u32, trace_sentinel, .big);

        const peer_idx = try pollOne(fds);
        const peer = self.peers[peer_idx];

        for (trace_buf) |*entry|
            entry.* = try peer.reader().readInt(u32, .big);
        log.info("Trace of potato: {any}", .{trace_buf});
    }

    pub fn shutdown(self: *@This()) void {
        for (self.peers) |peer| peer.close();
    }

    pub fn deinit(self: *@This()) void {
        self.allocator.free(self.peers);
    }
};

pub const Player = struct {
    allocator: std.mem.Allocator,
    trace_buf: std.ArrayListUnmanaged(u32),
    id: u32,
    ring_master: net.Stream,
    left_peer: net.Stream,
    right_peer: net.Stream,

    pub fn init(allocator: std.mem.Allocator) !@This() {
        return .{
            .allocator = allocator,
            .trace_buf = try .initCapacity(allocator, 2),
            .id = undefined,
            .ring_master = undefined,
            .left_peer = undefined,
            .right_peer = undefined,
        };
    }

    pub fn handshake(self: *@This(), rm_addr: net.Address, listen_addr: net.Address) !void {
        log.debug("handshake start", .{});
        var server: Server = undefined;
        try server.listen(listen_addr);
        defer server.deinit();

        self.ring_master = try net.tcpConnectToAddress(rm_addr);
        errdefer self.ring_master.close();
        log.debug("connected to ring master at {}", .{rm_addr});
        try self.ring_master.writer().writeInt(u16, server.getListenAddress().getPort(), .big);
        self.id = try self.ring_master.reader().readInt(u32, .big);
        log.info("Connected as player {}", .{self.id});
        const peer_addr = try recvAddress(self.ring_master);
        self.left_peer = try net.tcpConnectToAddress(peer_addr);
        log.debug("peer {} connected to left peer at {}", .{ self.id, peer_addr });
        errdefer self.left_peer.close();
        const conn = try server.accept();
        self.right_peer = conn.stream;
        errdefer self.right_peer.close();
        log.debug("peer {} connected to right peer at {}", .{ self.id, conn.address });
    }

    pub fn play(self: *@This(), rng: std.Random) !void {
        const streams = [_]net.Stream{
            self.ring_master,
            self.left_peer,
            self.right_peer,
        };
        var fds = [_]posix.pollfd{
            .{ .fd = self.ring_master.handle, .events = posix.POLL.IN, .revents = undefined },
            .{ .fd = self.left_peer.handle, .events = posix.POLL.IN, .revents = undefined },
            .{ .fd = self.right_peer.handle, .events = posix.POLL.IN, .revents = undefined },
        };
        while (true) {
            const peer_idx = pollOne(&fds) catch |err| {
                switch (err) {
                    // If remote dropped for whatever reason, shutdown.
                    error.RemoteError => break,
                    else => return err,
                }
            };
            const peer = streams[peer_idx];
            var ttl = try peer.reader().readInt(u32, .big);
            if (ttl == 0) {
                log.err("Unexpected ttl: {}", .{ttl});
                return error.ProtocolError;
            }
            try self.readTraceBuf(peer);
            const trace_buf_payload = std.mem.sliceAsBytes(self.trace_buf.items);
            var forward_peer: net.Stream = undefined;
            ttl -= 1;
            log.debug("ttl={}", .{ttl});
            if (ttl == 0) {
                log.info("I'm it.", .{});
                forward_peer = self.ring_master;
            } else {
                if (rng.boolean()) {
                    log.info("Sending potato to next", .{});
                    forward_peer = self.left_peer;
                } else {
                    log.info("Sending potato to prev", .{});
                    forward_peer = self.right_peer;
                }
                try forward_peer.writer().writeInt(u32, ttl, .big);
            }
            try forward_peer.writeAll(trace_buf_payload);
        }
    }

    pub fn readTraceBuf(self: *@This(), peer: net.Stream) !void {
        self.trace_buf.clearRetainingCapacity();
        while (true) {
            var trace_entry: u32 = undefined;
            const len = try peer.reader().readAll(std.mem.asBytes(&trace_entry));
            if (len != @sizeOf(@TypeOf(trace_entry))) {
                return error.ProtocolError;
            }
            if (trace_entry == trace_sentinel) { // endianness does not matter for 0xffffffff
                try self.trace_buf.appendSlice(self.allocator, &.{ std.mem.nativeToBig(u32, self.id), trace_sentinel });
                break;
            }
            try self.trace_buf.append(self.allocator, trace_entry);
        }
        log.debug("read trace of {} entries", .{self.trace_buf.items.len - 1});
    }

    pub fn shutdown(self: *@This()) void {
        self.right_peer.close();
        self.left_peer.close();
        self.ring_master.close();
    }

    pub fn deinit(self: *@This()) void {
        self.trace_buf.deinit(self.allocator);
    }
};

fn TestFixture(comptime n: usize, comptime hops: u32) type {
    return struct {
        has_error: bool = false,
        const ring_master_port: u16 = 8086;
        const loopback_ip = [4]u8{ 127, 0, 0, 1 };

        fn ring_master_thread(tid: usize) !void {
            assert(tid == 0);
            var ring_master = try RingMaster.init(testing.allocator, n);
            defer ring_master.deinit();

            const addr = net.Address.initIp4(loopback_ip, ring_master_port);
            try ring_master.handshake(addr);
            defer ring_master.shutdown();

            if (hops > 0) {
                var rng = std.Random.Xoshiro256.init(@intCast(tid));
                try ring_master.play(rng.random(), hops);
            }
        }
        fn player_thread(tid: usize) !void {
            assert(tid > 0);
            var player = try Player.init(testing.allocator);
            defer player.deinit();

            const player_port: u16 = ring_master_port + @as(u16, @intCast(tid));
            const player_addr = net.Address.initIp4(loopback_ip, player_port);
            const ring_master_addr = net.Address.initIp4(loopback_ip, ring_master_port);
            try player.handshake(ring_master_addr, player_addr);
            defer player.shutdown();

            if (hops > 0) {
                var rng = std.Random.Xoshiro256.init(@intCast(tid));
                try player.play(rng.random());
            }
        }
        fn wrapperInner(f: *const fn (usize) anyerror!void, tid: usize) !void {
            f(tid) catch |err| {
                std.debug.print("{}:{}", .{ err, @errorReturnTrace().? });
            };
        }
        fn wrapper(self: *@This(), f: *const fn (usize) anyerror!void, tid: usize) void {
            wrapperInner(f, tid) catch {
                self.has_error = true;
            };
        }
        fn run(self: *@This()) !void {
            var threads: [n + 1]std.Thread = undefined;
            inline for (&threads, 0..) |*t, tid| {
                t.* = try std.Thread.spawn(.{}, wrapper, .{
                    self,
                    if (tid == 0) ring_master_thread else player_thread,
                    tid,
                });
            }
            inline for (&threads) |*t| t.join();
            if (self.has_error)
                return error.ThreadError;
        }
    };
}

test "handshake - one player" {
    var fixture = TestFixture(1, 0){};
    try fixture.run();
}

test "handshake - two players" {
    var fixture = TestFixture(2, 0){};
    try fixture.run();
}

test "handshake - more players" {
    inline for (3..10) |n| {
        var fixture = TestFixture(n, 0){};
        try fixture.run();
    }
}

test "game - 1 player, 1 hop" {
    var fixture = TestFixture(1, 1){};
    try fixture.run();
}

test "game - 2 players, 10 hops" {
    var fixture = TestFixture(2, 10){};
    try fixture.run();
}

test "game - more players, 10 hops" {
    inline for (3..10) |n| {
        var fixture = TestFixture(n, 10){};
        try fixture.run();
    }
}
