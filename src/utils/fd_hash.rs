// Constants from Firedancer's fd_hash
const C1: u64 = 11400714785074694791;
const C2: u64 = 14029467366897019727;
const C3: u64 = 1609587929392839161;
const C4: u64 = 9650029242287828579;
const C5: u64 = 2870177450012600261;

#[inline(always)]
#[allow(clippy::arithmetic_side_effects)]
fn rotate_left(x: u64, r: u32) -> u64 {
    (x << r) | (x >> (64 - r))
}

/// Rust port of Firedancer's fd_hash
pub fn fd_hash(seed: u64, buf: &[u8]) -> u64 {
    let mut p = buf;
    let sz = buf.len() as u64;
    let mut h: u64;

    if sz < 32 {
        h = seed.wrapping_add(C5);
    } else {
        let mut w = seed.wrapping_add(C1.wrapping_add(C2));
        let mut x = seed.wrapping_add(C2);
        let mut y = seed;
        let mut z = seed.wrapping_sub(C1);

        while p.len() >= 32 {
            let p0 = u64::from_le_bytes(p[0..8].try_into().unwrap());
            let p1 = u64::from_le_bytes(p[8..16].try_into().unwrap());
            let p2 = u64::from_le_bytes(p[16..24].try_into().unwrap());
            let p3 = u64::from_le_bytes(p[24..32].try_into().unwrap());
            w = w.wrapping_add(p0.wrapping_mul(C2));
            w = rotate_left(w, 31);
            w = w.wrapping_mul(C1);

            x = x.wrapping_add(p1.wrapping_mul(C2));
            x = rotate_left(x, 31);
            x = x.wrapping_mul(C1);

            y = y.wrapping_add(p2.wrapping_mul(C2));
            y = rotate_left(y, 31);
            y = y.wrapping_mul(C1);

            z = z.wrapping_add(p3.wrapping_mul(C2));
            z = rotate_left(z, 31);
            z = z.wrapping_mul(C1);

            p = &p[32..];
        }

        h = rotate_left(w, 1)
            .wrapping_add(rotate_left(x, 7))
            .wrapping_add(rotate_left(y, 12))
            .wrapping_add(rotate_left(z, 18));

        for v in [w, x, y, z] {
            let mut vv = v.wrapping_mul(C2);
            vv = rotate_left(vv, 31);
            vv = vv.wrapping_mul(C1);
            h ^= vv;
            h = h.wrapping_mul(C1).wrapping_add(C4);
        }
    }

    h = h.wrapping_add(sz);

    while p.len() >= 8 {
        let w = u64::from_le_bytes(p[0..8].try_into().unwrap());
        let mut ww = w.wrapping_mul(C2);
        ww = rotate_left(ww, 31);
        ww = ww.wrapping_mul(C1);
        h ^= ww;
        h = rotate_left(h, 27).wrapping_mul(C1).wrapping_add(C4);
        p = &p[8..];
    }

    if p.len() >= 4 {
        let w = u32::from_le_bytes(p[0..4].try_into().unwrap()) as u64;
        let ww = w.wrapping_mul(C1);
        h ^= ww;
        h = rotate_left(h, 23).wrapping_mul(C2).wrapping_add(C3);
        p = &p[4..];
    }

    for &byte in p {
        let w = (byte as u64).wrapping_mul(C5);
        h ^= w;
        h = rotate_left(h, 11).wrapping_mul(C1);
    }

    // Final avalanche
    h ^= h >> 33;
    h = h.wrapping_mul(C2);
    h ^= h >> 29;
    h = h.wrapping_mul(C3);
    h ^= h >> 32;

    h
}
