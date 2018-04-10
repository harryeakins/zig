const warn = @import("std").debug.warn;
const math = @import("std").math;
const assert = @import("std").debug.assert;
const mem = @import("std").mem;
const std = @import("std");

const AesError = error {
    KeyLengthError,
};  

fn xtime(x: u8) u8 {
    var z: u8 = 0x00;
    if(x & 0x80 == 0x80) z = 0x1B;
    return (x << 1) ^ z;
}

fn pow_table() [256]u8 {
    var _pow = []u8{0} ** 256;
    var x: u8 = 1;
    for(_pow) |*v, i| {
        *v = x;
        x = x ^ xtime(x);
    }
    return _pow;
}

fn log_table() [256]u8 {
    var _log = []u8{0} ** 256;
    for(pow[0..255]) |v, i| {
        _log[v] = u8(i);
    }
    return _log;
}

fn rcon_table() [10]u8 {
    var res = []u8{0} ** 10;
    var x: u8 = 1;
    for(res) |*v, i| {
        *v = x;
        x = xtime(x);
    }
    
    return res;
}

fn mul(x: u8, y: u8) u8 {
    return pow[(usize(log[x]) + usize(log[y])) % 255];
}

fn inv(x: u8) u8 {
    return pow[255 - log[x]];
}

fn gen_fsbox() [256]u8 {
    var res = []u8{0}**256;
    
    res[0] = 0x63;
    
    for(res) |*v, i| {
        if(i == 0) continue;
        var x = inv(u8(i));
        var y = x;
        var j = u8(0);
        while(j < 4) : (j += 1) {
            y = math.rotl(u8, y, u8(1));
            x ^= y;
        }
        x ^= 0x63;

        *v = x;
    }
    return res;
}

fn gen_rsbox() [256]u8 {
    var res = []u8{0}**256;
    
    for(fsbox) |v, i| {
        res[v] = u8(i);
    }
    return res;
}

fn gen_ftable(n: usize) [256]u32 {
    var res = []u32{0}**256;
    var i = usize(0);
    while(i < 256) : (i += 1) {
        var x = fsbox[i];
        var y = xtime(x);
        var z = y ^ x;
        
        var r = u32(y) | u32(x) << 8 | u32(x) << 16 | u32(z) << 24;
        res[i] = math.rotl(u32, r, n*8);
    }
    return res;
}

fn gen_rtable(n: usize) [256]u32 {
    var res = []u32{0}**256;
    var i = usize(0);
    while(i < 256) : (i += 1) {
        var x = rsbox[i];
        
        var r = u32(mul(0x0E, x)) | u32(mul(0x09, x)) << 8 | u32(mul(0x0D, x)) << 16 | u32(mul(0x0B, x)) << 24;
        res[i] = math.rotl(u32, r, n*8);
    }
    return res;
}

fn key_sched_core(i: usize, in: u32) u32 {
    var res = u32(0);
    var tmp = u32(math.rotr(u32, in, u8(8)));
    comptime var j = 0;
    inline while(j < 4) : (j += 1) {
        var x = u8((tmp >> (8*j)) & 0xFF);
        x = fsbox[x];
        res |= u32(x) << (8*j);
    }
    return res ^ (u32(rcon[i]));
}

fn word_to_bytes(word: u32, bytes: []u8, pos: usize) void {
    bytes[pos]   = u8((word      ) & 0xFF);
    bytes[pos+1] = u8((word >> 8 ) & 0xFF);
    bytes[pos+2] = u8((word >> 16) & 0xFF);
    bytes[pos+3] = u8((word >> 24) & 0xFF);
}

fn bytes_to_word(bytes: []u8, pos: usize) u32 {
    return  u32(bytes[pos  ]) | 
            u32(bytes[pos+1]) << 8 |
            u32(bytes[pos+2]) << 16 |
            u32(bytes[pos+3]) << 24;
}

pub fn gen_round_keys(key: []u8, RK: []u32) !void {
    return switch(key.len) {
        16 => blk: {
            comptime var i = 0; // Num words in the expanded key
            inline while(i < 4) : (i += 1) {
                RK[i] = bytes_to_word(key, 4*i);
            }

            inline while(i < 44) : (i += 4) {
                RK[i] = RK[i-4] ^ key_sched_core((i-4)/4, RK[i-1]);

                RK[i+1] = RK[i-3] ^ RK[i];
                RK[i+2] = RK[i-2] ^ RK[i+1];
                RK[i+3] = RK[i-1] ^ RK[i+2];
            }

            break :blk {};
        },
        else => AesError.KeyLengthError,
    };
}

fn aes_fround(RK: []u32, _X: &[4]u32) [4]u32 {
    var X = *_X;
    var res = []u32{0} ** 4;
    res[0] = RK[0] ^ ftable0[(X[0]      ) & 0xFF] ^
                     ftable1[(X[1] >>  8) & 0xFF] ^
                     ftable2[(X[2] >> 16) & 0xFF] ^
                     ftable3[(X[3] >> 24) & 0xFF];
    res[1] = RK[1] ^ ftable0[(X[1]      ) & 0xFF] ^
                     ftable1[(X[2] >>  8) & 0xFF] ^
                     ftable2[(X[3] >> 16) & 0xFF] ^
                     ftable3[(X[0] >> 24) & 0xFF];

    res[2] = RK[2] ^ ftable0[(X[2]      ) & 0xFF] ^
                     ftable1[(X[3] >>  8) & 0xFF] ^
                     ftable2[(X[0] >> 16) & 0xFF] ^
                     ftable3[(X[1] >> 24) & 0xFF];

    res[3] = RK[3] ^ ftable0[(X[3]      ) & 0xFF] ^
                     ftable1[(X[0] >>  8) & 0xFF] ^
                     ftable2[(X[1] >> 16) & 0xFF] ^
                     ftable3[(X[2] >> 24) & 0xFF];

    return res;
}

pub fn encrypt(RK: []u32, input: &[16]u8) [16]u8 {
    var res = []u32{0} ** 4;
    var X = []u32{0}**4;
    var Y = []u32{0}**4;

    X[0] = bytes_to_word((*input)[0..], 0) ^ RK[0];
    X[1] = bytes_to_word((*input)[0..], 4) ^ RK[1];
    X[2] = bytes_to_word((*input)[0..], 8) ^ RK[2];
    X[3] = bytes_to_word((*input)[0..], 12) ^ RK[3];

    var i = usize(4);
    while(i <  RK.len-4) : (i += 4) {
        X = aes_fround(RK[i..], &X);
    }

    res[0] = RK[i] ^ u32(fsbox[(X[0]      ) & 0xFF]) ^
                     u32(fsbox[(X[1] >>  8) & 0xFF]) << 8  ^
                     u32(fsbox[(X[2] >> 16) & 0xFF]) << 16 ^
                     u32(fsbox[(X[3] >> 24) & 0xFF]) << 24;

    res[1] = RK[i+1] ^ u32(fsbox[(X[1]      ) & 0xFF]) ^
                     u32(fsbox[(X[2] >>  8) & 0xFF]) << 8  ^
                     u32(fsbox[(X[3] >> 16) & 0xFF]) << 16 ^
                     u32(fsbox[(X[0] >> 24) & 0xFF]) << 24;

    res[2] = RK[i+2] ^ u32(fsbox[(X[2]      ) & 0xFF]) ^
                     u32(fsbox[(X[3] >>  8) & 0xFF]) << 8  ^
                     u32(fsbox[(X[0] >> 16) & 0xFF]) << 16 ^
                     u32(fsbox[(X[1] >> 24) & 0xFF]) << 24;

    res[3] = RK[i+3] ^ u32(fsbox[(X[3]      ) & 0xFF]) ^
                     u32(fsbox[(X[0] >>  8) & 0xFF]) << 8  ^
                     u32(fsbox[(X[1] >> 16) & 0xFF]) << 16 ^
                     u32(fsbox[(X[2] >> 24) & 0xFF]) << 24;

    var _res = []u8{0} ** 16;
    
    word_to_bytes(res[0], _res[0..], 0);
    word_to_bytes(res[1], _res[0..], 4);
    word_to_bytes(res[2], _res[0..], 8);
    word_to_bytes(res[3], _res[0..], 12);
    
    return _res;
}

const pow = pow_table();
const log = log_table();

const rcon = rcon_table();

const fsbox = blk: { @setEvalBranchQuota(10000); break :blk gen_fsbox(); };
const rsbox = blk: { @setEvalBranchQuota(10000); break :blk gen_rsbox(); };

const ftable0 = blk: { @setEvalBranchQuota(10000); break :blk gen_ftable(0); };
const ftable1 = blk: { @setEvalBranchQuota(10000); break :blk gen_ftable(1); };
const ftable2 = blk: { @setEvalBranchQuota(10000); break :blk gen_ftable(2); };
const ftable3 = blk: { @setEvalBranchQuota(10000); break :blk gen_ftable(3); };

const rtable0 = blk: { @setEvalBranchQuota(10000); break :blk gen_rtable(0); };
const rtable1 = blk: { @setEvalBranchQuota(10000); break :blk gen_rtable(1); };
const rtable2 = blk: { @setEvalBranchQuota(10000); break :blk gen_rtable(2); };
const rtable3 = blk: { @setEvalBranchQuota(10000); break :blk gen_rtable(3); };


test "checking pow works" {
    for(pow) |v, i| {
        if(i % 16 == 0) warn("\n");
        warn("{x02} ", v);
    }
    warn("\n");
}

test "checking log works" {
    for(log) |v, i| {
        if(i % 16 == 0) warn("\n");
        warn("{x02} ", v);
    }
    warn("\n");
}

test "using log pow tables" {
    warn("log(0x52) = {} log(0x0E) = {}\n", log[0x52], log[0x0E]);
    warn("253 +% 223 = {}\n", u8(253) +% u8(223));
    warn("{x02} * {x02} = {x02}\n", u8(0x52), u8(0x0E), mul(0x52, 0x0E));
    warn("{x02} * {x02} = {x02}\n", u8(0x52), u8(0x0E), mul(0x52, 0x0E));
    warn("inv({x02}) = {x02}\n", u8(0xb6), inv(0xb6));
    warn("{x02} * {x02} = {x02}\n", u8(0xb6), inv(0xb6), mul(0xb6, inv(0xb6)));
}

test "checking rcon works" {
    for(rcon) |v, i| {
        if(i % 16 == 0) warn("\n");
        warn("{x02} ", v);
    }
    warn("\n");
}

test "checking fsbox works" {
    for(fsbox) |v, i| {
        if(i % 16 == 0) warn("\n");
        warn("{x02} ", v);
    }
    warn("\n");
}

test "checking rsbox works" {
    for(rsbox) |v, i| {
        if(i % 16 == 0) warn("\n");
        warn("{x02} ", v);
    }
    warn("\n");
}

test "checking ftable works" {
    for(ftable0) |v, i| {
        if(i % 16 == 0) warn("\n");
        warn("{x08} ", v);
    }
    warn("\n");
    assert(ftable0[3] == 0x8D7B7Bf6);
    assert(ftable1[5] == 0x6B6BD6BD);

    warn("ftable0[0x63] => {x08}\n", ftable0[0x63]);
    warn("ftable1[0x63] => {x08}\n", ftable1[0x63]);
    warn("ftable2[0x63] => {x08}\n", ftable2[0x63]);
    warn("ftable3[0x63] => {x08}\n", ftable3[0x63]);
}

test "checking rtable works" {
    for(rtable0) |v, i| {
        if(i % 16 == 0) warn("\n");
        warn("{x08} ", v);
    }
    warn("\n");
    assert(rtable0[3] == 0x965E273A);
    assert(rtable1[5] == 0x459D1FF1);
}

test "checking key_sched_core" {
    warn("key_sched_core(0, 0x12345678) = {x08}\n", key_sched_core(0, 0x12345678));
}

test "checking gen_round_keys" {
    {
        var key = []u8{0} ** 16;
        var RK = []u32{0} ** 44;
        try gen_round_keys(key[0..], RK[0..]);

        warn("gen_round_keys(0x00) = ");
        for(RK) |*v, i| {
            if(i % 4 == 0) warn("\n");
            warn("{x08} ", *v);
        }
        warn("\n\n");
    }

    {
        var key = []u8{0xFF} ** 16;
        var RK = []u32{0} ** 44;
        try gen_round_keys(key[0..], RK[0..]);

        warn("gen_round_keys(0xFF) = ");
        for(RK) |*v, i| {
            if(i % 4 == 0) warn("\n");
            warn("{x08} ", *v);
        }
        warn("\n\n");
    }
}

test "fround" {
    var key = []u8{0} ** 16;
    var RK = []u32{0} ** 44;
    try gen_round_keys(key[0..], RK[0..]);

    var X = []u32{0, 1, 2, 3};
    var Y = aes_fround(RK[0..], &X);

    warn("aes_fround({x08}{x08}{x08}{x08}, {x08}{x08}{x08}{x08}) => {x08}{x08}{x08}{x08}\n",
                    RK[0], RK[1], RK[2], RK[3],
                    X[0], X[1], X[2], X[3],
                    Y[0], Y[1], Y[2], Y[3]);
}

test "aes-128" {
    {
        var key = []u8{0x2b, 0x7e, 0x15, 0x16,
                       0x28, 0xae, 0xd2, 0xa6,
                       0xab, 0xf7, 0x15, 0x88,
                       0x09, 0xcf, 0x4f, 0x3c};

        var RK = []u32{0} ** 44;
        try gen_round_keys(key[0..], RK[0..]);

        var plain = []u8{0x6b, 0xc1, 0xbe, 0xe2,
                         0x2e, 0x40, 0x9f, 0x96,
                         0xe9, 0x3d, 0x7e, 0x11,
                         0x73, 0x93, 0x17, 0x2a};

        var enc = encrypt(RK[0..], &plain);

        warn("encrypt_key = 2b7e151628aed2a6abf7158809cf4f3c, plaintext = 6bc1bee22e409f96e93d7e117393172a\n");
        for(enc) |word| {
            warn("{x02}", word);
        }
        warn("\n\n");
    }

    {
        var key = []u8{0} ** 16;
        var RK = []u32{0} ** 44;

        try gen_round_keys(key[0..], RK[0..]);

        var plain = []u8{0} ** 16;

        var enc = encrypt(RK[0..], &plain);

        warn("encrypt_key = 0x00, plaintext = 0x00\n");
        for(enc) |word| {
            warn("{x02}", word);
        }
        warn("\n\n");
    }
}
