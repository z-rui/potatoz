const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const ring_master_exe = b.addExecutable(.{
        .name = "ring_master",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/ring_master_main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const player_exe = b.addExecutable(.{
        .name = "player",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/player_main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(ring_master_exe);
    b.installArtifact(player_exe);

    const test_step = b.step("test", "Run unit tests");
    const unit_tests = b.addRunArtifact(b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/potato.zig"),
            .target = target,
            .optimize = optimize,
        }),
    }));

    test_step.dependOn(&unit_tests.step);
}
