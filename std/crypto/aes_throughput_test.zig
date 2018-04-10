// Modify the HashFunction variable to the one wanted to test.
//
// NOTE: The throughput measurement may be slightly lower than other measurements since we run
// through our block alignment functions as well. Be aware when comparing against other tests.
//
// ```
// zig build-exe --release-fast --library c throughput_test.zig
// ./throughput_test
// ```

const std = @import("std");
const c = @cImport({
    @cInclude("time.h");
});

const aes = @import("aes.zig");

const bytes_per_encryption = 16;
const num_encryptions = 1000000;
const MiB = 1024 * 1024;

pub fn main() !void {
    var stdout_file = try std.io.getStdOut();
    var stdout_out_stream = std.io.FileOutStream.init(&stdout_file);
    const stdout = &stdout_out_stream.stream;

    var block = []u8{0} ** 16;

    const start = c.clock();

    var i: usize = 0;
    while(i < num_encryptions) : (i += 1) {
        var RK = []u32{0} ** 44;
        try aes.gen_round_keys(block[0..], RK[0..]);
        var tmp = aes.encrypt(RK[0..], &block);
        std.mem.copy(u8, block[0..], tmp);
    }
    const end = c.clock();

    const elapsed_s = f64(end - start) / f64(c.CLOCKS_PER_SEC);
    const throughput = u64(num_encryptions * bytes_per_encryption / elapsed_s);

    try stdout.print("aes: {} MiB/s\n", throughput / (1 * MiB));
}
