//! MuHash3072 (Bitcoin Core `crypto/muhash.cpp`, v30.0): an incremental,
//! order-independent multiset hash over the group Z_p^*, p = 2^3072 - 1103717.
//! Design record 5065900 (set-hash projection digest), slice 1.
//!
//! Self-contained on purpose (std, `sha2`, `chacha20` only), so the arithmetic
//! can be benchmarked and audited apart from the database.
//!
//! * An element is mapped to the group exactly as Core does: `key =
//!   SHA256(element)`, 384 bytes of ChaCha20 keystream under that key (RFC 8439,
//!   96-bit zero nonce, counter 0), read as a little-endian integer. Core does
//!   NOT reduce that integer at mapping time (a value >= p is just another
//!   representative) and has no "0 becomes 1" rule (probability 2^-3052); this
//!   module follows Core on both, and treats representatives as congruent mod p.
//! * A set is a numerator and a denominator; insert multiplies the numerator,
//!   remove multiplies the denominator, and the denominator is inverted once, at
//!   normalisation. The digest is `SHA256` of the 384-byte little-endian
//!   normalised value.
// Wired into the digest by later slices; unused combinators are intended API.
// The index loops and `from_*(&mut self, ..)` mirror Core's limb code one to
// one, which is what makes the port auditable against the reference.
#![allow(dead_code, clippy::needless_range_loop, clippy::wrong_self_convention)]

use chacha20::cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha256};

const LIMBS: usize = 48;
const SIGNED_LIMBS: usize = 50;
const LIMB_SIZE: u32 = 64;
const SIGNED_LIMB_SIZE: u32 = 62;
const FINAL_LIMB_POSITION: usize = 3072 / SIGNED_LIMB_SIZE as usize;
const FINAL_LIMB_MODULUS_BITS: u32 = 3072 % SIGNED_LIMB_SIZE;
const MAX_SIGNED_LIMB: u64 = (1 << SIGNED_LIMB_SIZE) - 1;
/// 2^3072 - MAX_PRIME_DIFF is the modulus.
const MAX_PRIME_DIFF: u64 = 1_103_717;
/// Inverse of the modulus mod 2^62.
const MODULUS_INVERSE: u64 = 0x070a_1421_da08_7d93;

pub(crate) const BYTE_SIZE: usize = 384;

/// A 3072-bit number, possibly not fully reduced (value < 2^3072).
#[derive(Clone, Debug)]
pub(crate) struct Num3072 {
    limbs: [u64; LIMBS],
}

#[inline]
fn extract3(c0: &mut u64, c1: &mut u64, c2: &mut u64) -> u64 {
    let n = *c0;
    *c0 = *c1;
    *c1 = *c2;
    *c2 = 0;
    n
}

/// [c0,c1,c2] += a * b
#[inline]
fn muladd3(c0: &mut u64, c1: &mut u64, c2: &mut u64, a: u64, b: u64) {
    let t = (a as u128) * (b as u128);
    let mut th = (t >> 64) as u64;
    let tl = t as u64;
    *c0 = c0.wrapping_add(tl);
    th += u64::from(*c0 < tl);
    *c1 = c1.wrapping_add(th);
    *c2 += u64::from(*c1 < th);
}

/// [c0,c1,c2] += n * [d0,d1,d2]; c2 is 0 initially.
#[inline]
fn mulnadd3(c0: &mut u64, c1: &mut u64, c2: &mut u64, d0: u64, d1: u64, d2: u64, n: u64) {
    let mut t = (d0 as u128) * (n as u128) + (*c0 as u128);
    *c0 = t as u64;
    t >>= 64;
    t += (d1 as u128) * (n as u128) + (*c1 as u128);
    *c1 = t as u64;
    t >>= 64;
    *c2 = (t as u64).wrapping_add(d2.wrapping_mul(n));
}

/// [c0,c1] *= n
#[inline]
fn muln2(c0: &mut u64, c1: &mut u64, n: u64) {
    let mut t = (*c0 as u128) * (n as u128);
    *c0 = t as u64;
    t >>= 64;
    t += (*c1 as u128) * (n as u128);
    *c1 = t as u64;
}

/// [c0,c1] += a; then return the low limb and shift right by one limb.
#[inline]
fn addnextract2(c0: &mut u64, c1: &mut u64, a: u64) -> u64 {
    let mut c2 = 0;
    *c0 = c0.wrapping_add(a);
    if *c0 < a {
        *c1 = c1.wrapping_add(1);
        if *c1 == 0 {
            c2 = 1;
        }
    }
    let n = *c0;
    *c0 = *c1;
    *c1 = c2;
    n
}

impl Num3072 {
    pub(crate) fn one() -> Self {
        let mut limbs = [0; LIMBS];
        limbs[0] = 1;
        Self { limbs }
    }

    /// Little-endian, as Core reads keystream and serialised values.
    pub(crate) fn from_le_bytes(bytes: &[u8; BYTE_SIZE]) -> Self {
        let mut limbs = [0; LIMBS];
        for (limb, chunk) in limbs.iter_mut().zip(bytes.as_chunks::<8>().0) {
            *limb = u64::from_le_bytes(*chunk);
        }
        Self { limbs }
    }

    pub(crate) fn to_le_bytes(&self) -> [u8; BYTE_SIZE] {
        let mut out = [0; BYTE_SIZE];
        for (chunk, limb) in out.as_chunks_mut::<8>().0.iter_mut().zip(self.limbs) {
            *chunk = limb.to_le_bytes();
        }
        out
    }

    /// Map a 32-byte key (the SHA-256 of an element) into the group.
    pub(crate) fn from_key(key: &[u8; 32]) -> Self {
        let mut stream = [0_u8; BYTE_SIZE];
        let mut cipher = chacha20::ChaCha20::new(key.into(), &[0_u8; 12].into());
        cipher.apply_keystream(&mut stream);
        Self::from_le_bytes(&stream)
    }

    fn is_overflow(&self) -> bool {
        if self.limbs[0] <= u64::MAX - MAX_PRIME_DIFF {
            return false;
        }
        self.limbs[1..].iter().all(|limb| *limb == u64::MAX)
    }

    fn full_reduce(&mut self) {
        let mut c0 = MAX_PRIME_DIFF;
        let mut c1 = 0;
        for limb in &mut self.limbs {
            *limb = addnextract2(&mut c0, &mut c1, *limb);
        }
    }

    /// self *= a (mod p). The result may be left unreduced in [p, 2^3072).
    pub(crate) fn multiply(&mut self, a: &Num3072) {
        let (mut c0, mut c1, mut c2) = (0_u64, 0_u64, 0_u64);
        let mut tmp = [0_u64; LIMBS];
        // Limbs 0..N-2 of self*a, including one reduction.
        for j in 0..LIMBS - 1 {
            let t = (self.limbs[1 + j] as u128) * (a.limbs[LIMBS - 1] as u128);
            let (mut d0, mut d1, mut d2) = (t as u64, (t >> 64) as u64, 0_u64);
            for i in 2 + j..LIMBS {
                muladd3(
                    &mut d0,
                    &mut d1,
                    &mut d2,
                    self.limbs[i],
                    a.limbs[LIMBS + j - i],
                );
            }
            mulnadd3(&mut c0, &mut c1, &mut c2, d0, d1, d2, MAX_PRIME_DIFF);
            for i in 0..j + 1 {
                muladd3(&mut c0, &mut c1, &mut c2, self.limbs[i], a.limbs[j - i]);
            }
            tmp[j] = extract3(&mut c0, &mut c1, &mut c2);
        }
        debug_assert_eq!(c2, 0);
        // Limb N-1.
        for i in 0..LIMBS {
            muladd3(
                &mut c0,
                &mut c1,
                &mut c2,
                self.limbs[i],
                a.limbs[LIMBS - 1 - i],
            );
        }
        tmp[LIMBS - 1] = extract3(&mut c0, &mut c1, &mut c2);
        // Second reduction.
        muln2(&mut c0, &mut c1, MAX_PRIME_DIFF);
        for j in 0..LIMBS {
            self.limbs[j] = addnextract2(&mut c0, &mut c1, tmp[j]);
        }
        debug_assert_eq!(c1, 0);
        debug_assert!(c0 == 0 || c0 == 1);
        if self.is_overflow() {
            self.full_reduce();
        }
        if c0 != 0 {
            self.full_reduce();
        }
    }

    /// The raw 48x48-limb product without any reduction (benchmark floor:
    /// what multiplication alone costs before reduction is added).
    pub(crate) fn raw_product(&self, a: &Num3072) -> [u64; 2 * LIMBS] {
        let mut out = [0_u64; 2 * LIMBS];
        for i in 0..LIMBS {
            let mut carry = 0_u128;
            for j in 0..LIMBS {
                let t =
                    (self.limbs[i] as u128) * (a.limbs[j] as u128) + (out[i + j] as u128) + carry;
                out[i + j] = t as u64;
                carry = t >> 64;
            }
            out[i + LIMBS] = carry as u64;
        }
        out
    }

    /// self /= a (mod p): one inversion.
    pub(crate) fn divide(&mut self, a: &Num3072) {
        if self.is_overflow() {
            self.full_reduce();
        }
        let inverse = if a.is_overflow() {
            let mut b = a.clone();
            b.full_reduce();
            b.inverse()
        } else {
            a.inverse()
        };
        self.multiply(&inverse);
        if self.is_overflow() {
            self.full_reduce();
        }
    }

    /// The modular inverse (safegcd, Core's `Num3072::GetInverse`). The input
    /// must be fully reduced and non-zero.
    pub(crate) fn inverse(&self) -> Num3072 {
        let mut d = Signed::zero();
        let mut e = Signed::zero();
        let mut f = Signed::zero();
        let mut g = Signed::zero();
        e.limbs[0] = 1;
        f.limbs[0] = -(MAX_PRIME_DIFF as i64);
        f.limbs[FINAL_LIMB_POSITION] = 1_i64 << FINAL_LIMB_MODULUS_BITS;
        g.from_num(self);
        let mut len = SIGNED_LIMBS;
        let mut eta: i64 = -1;
        loop {
            let (new_eta, t) = compute_divstep_matrix(eta, f.limbs[0] as u64, g.limbs[0] as u64);
            eta = new_eta;
            update_fg(&mut f, &mut g, &t, len);
            update_de(&mut d, &mut e, &t);
            if g.limbs[0] == 0 {
                let mut cond = 0_i64;
                for j in 1..len {
                    cond |= g.limbs[j];
                }
                if cond == 0 {
                    break;
                }
            }
            let fn_ = f.limbs[len - 1];
            let gn = g.limbs[len - 1];
            let mut cond = ((len as i64) - 2) >> (LIMB_SIZE - 1);
            cond |= fn_ ^ (fn_ >> (LIMB_SIZE - 1));
            cond |= gn ^ (gn >> (LIMB_SIZE - 1));
            if cond == 0 {
                f.limbs[len - 2] |= ((f.limbs[len - 1] as u64) << SIGNED_LIMB_SIZE) as i64;
                g.limbs[len - 2] |= ((g.limbs[len - 1] as u64) << SIGNED_LIMB_SIZE) as i64;
                len -= 1;
            }
        }
        d.normalize((f.limbs[len - 1] >> (LIMB_SIZE - 1)) != 0);
        d.to_num()
    }
}

/// A number in 62-bit signed limbs.
struct Signed {
    limbs: [i64; SIGNED_LIMBS],
}

impl Signed {
    fn zero() -> Self {
        Self {
            limbs: [0; SIGNED_LIMBS],
        }
    }

    fn from_num(&mut self, input: &Num3072) {
        let mut c: u128 = 0;
        let mut b: u32 = 0;
        let mut outpos = 0;
        for limb in input.limbs {
            c += (limb as u128) << b;
            b += LIMB_SIZE;
            while b >= SIGNED_LIMB_SIZE {
                self.limbs[outpos] = ((c as u64) & MAX_SIGNED_LIMB) as i64;
                outpos += 1;
                c >>= SIGNED_LIMB_SIZE;
                b -= SIGNED_LIMB_SIZE;
            }
        }
        debug_assert_eq!(outpos, SIGNED_LIMBS - 1);
        self.limbs[SIGNED_LIMBS - 1] = c as i64;
    }

    fn to_num(&self) -> Num3072 {
        let mut out = [0_u64; LIMBS];
        let mut c: u128 = 0;
        let mut b: u32 = 0;
        let mut outpos = 0;
        for limb in self.limbs {
            c = c.wrapping_add((limb as i128 as u128) << b);
            b += SIGNED_LIMB_SIZE;
            if b >= LIMB_SIZE {
                out[outpos] = c as u64;
                outpos += 1;
                c >>= LIMB_SIZE;
                b -= LIMB_SIZE;
            }
        }
        debug_assert_eq!(outpos, LIMBS);
        Num3072 { limbs: out }
    }

    fn normalize(&mut self, negate: bool) {
        let modulus_bit = 1_i64 << FINAL_LIMB_MODULUS_BITS;
        let diff = -(MAX_PRIME_DIFF as i64);
        let mut cond_add = self.limbs[SIGNED_LIMBS - 1] >> (LIMB_SIZE - 1);
        self.limbs[0] += diff & cond_add;
        self.limbs[FINAL_LIMB_POSITION] += modulus_bit & cond_add;
        let cond_negate = -(negate as i64);
        for limb in &mut self.limbs {
            *limb = (*limb ^ cond_negate) - cond_negate;
        }
        for i in 0..SIGNED_LIMBS - 1 {
            self.limbs[i + 1] += self.limbs[i] >> SIGNED_LIMB_SIZE;
            self.limbs[i] &= MAX_SIGNED_LIMB as i64;
        }
        cond_add = self.limbs[SIGNED_LIMBS - 1] >> (LIMB_SIZE - 1);
        self.limbs[0] += diff & cond_add;
        self.limbs[FINAL_LIMB_POSITION] += modulus_bit & cond_add;
        for i in 0..SIGNED_LIMBS - 1 {
            self.limbs[i + 1] += self.limbs[i] >> SIGNED_LIMB_SIZE;
            self.limbs[i] &= MAX_SIGNED_LIMB as i64;
        }
    }
}

struct SignedMatrix {
    u: i64,
    v: i64,
    q: i64,
    r: i64,
}

/// inv256[i] = -1/(2*i+1) (mod 256)
const NEGINV256: [u8; 128] = [
    0xFF, 0x55, 0x33, 0x49, 0xC7, 0x5D, 0x3B, 0x11, 0x0F, 0xE5, 0xC3, 0x59, 0xD7, 0xED, 0xCB, 0x21,
    0x1F, 0x75, 0x53, 0x69, 0xE7, 0x7D, 0x5B, 0x31, 0x2F, 0x05, 0xE3, 0x79, 0xF7, 0x0D, 0xEB, 0x41,
    0x3F, 0x95, 0x73, 0x89, 0x07, 0x9D, 0x7B, 0x51, 0x4F, 0x25, 0x03, 0x99, 0x17, 0x2D, 0x0B, 0x61,
    0x5F, 0xB5, 0x93, 0xA9, 0x27, 0xBD, 0x9B, 0x71, 0x6F, 0x45, 0x23, 0xB9, 0x37, 0x4D, 0x2B, 0x81,
    0x7F, 0xD5, 0xB3, 0xC9, 0x47, 0xDD, 0xBB, 0x91, 0x8F, 0x65, 0x43, 0xD9, 0x57, 0x6D, 0x4B, 0xA1,
    0x9F, 0xF5, 0xD3, 0xE9, 0x67, 0xFD, 0xDB, 0xB1, 0xAF, 0x85, 0x63, 0xF9, 0x77, 0x8D, 0x6B, 0xC1,
    0xBF, 0x15, 0xF3, 0x09, 0x87, 0x1D, 0xFB, 0xD1, 0xCF, 0xA5, 0x83, 0x19, 0x97, 0xAD, 0x8B, 0xE1,
    0xDF, 0x35, 0x13, 0x29, 0xA7, 0x3D, 0x1B, 0xF1, 0xEF, 0xC5, 0xA3, 0x39, 0xB7, 0xCD, 0xAB, 0x01,
];

fn compute_divstep_matrix(mut eta: i64, mut f: u64, mut g: u64) -> (i64, SignedMatrix) {
    let (mut u, mut v, mut q, mut r) = (1_u64, 0_u64, 0_u64, 1_u64);
    let mut i = SIGNED_LIMB_SIZE as i32;
    loop {
        let zeros = (g | (u64::MAX << i)).trailing_zeros() as i32;
        g >>= zeros;
        u = u.wrapping_shl(zeros as u32);
        v = v.wrapping_shl(zeros as u32);
        eta -= zeros as i64;
        i -= zeros;
        if i == 0 {
            break;
        }
        if eta < 0 {
            eta = -eta;
            let tmp = f;
            f = g;
            g = tmp.wrapping_neg();
            let tmp = u;
            u = q;
            q = tmp.wrapping_neg();
            let tmp = v;
            v = r;
            r = tmp.wrapping_neg();
        }
        let limit = if (eta as i32 + 1) > i {
            i
        } else {
            eta as i32 + 1
        };
        let m = (u64::MAX >> (LIMB_SIZE as i32 - limit)) & 255;
        let w = g.wrapping_mul(NEGINV256[((f >> 1) & 127) as usize] as u64) & m;
        g = g.wrapping_add(f.wrapping_mul(w));
        q = q.wrapping_add(u.wrapping_mul(w));
        r = r.wrapping_add(v.wrapping_mul(w));
    }
    (
        eta,
        SignedMatrix {
            u: u as i64,
            v: v as i64,
            q: q as i64,
            r: r as i64,
        },
    )
}

fn update_de(d: &mut Signed, e: &mut Signed, t: &SignedMatrix) {
    let (u, v, q, r) = (t.u, t.v, t.q, t.r);
    let sd = d.limbs[SIGNED_LIMBS - 1] >> (LIMB_SIZE - 1);
    let se = e.limbs[SIGNED_LIMBS - 1] >> (LIMB_SIZE - 1);
    let mut md = (u & sd) + (v & se);
    let mut me = (q & sd) + (r & se);
    let mut di = d.limbs[0];
    let mut ei = e.limbs[0];
    let mut cd: i128 = (u as i128) * (di as i128) + (v as i128) * (ei as i128);
    let mut ce: i128 = (q as i128) * (di as i128) + (r as i128) * (ei as i128);
    md = md.wrapping_sub(
        (MODULUS_INVERSE
            .wrapping_mul(cd as u64)
            .wrapping_add(md as u64)
            & MAX_SIGNED_LIMB) as i64,
    );
    me = me.wrapping_sub(
        (MODULUS_INVERSE
            .wrapping_mul(ce as u64)
            .wrapping_add(me as u64)
            & MAX_SIGNED_LIMB) as i64,
    );
    cd -= 1_103_717_i128 * (md as i128);
    ce -= 1_103_717_i128 * (me as i128);
    debug_assert_eq!((cd as u64) & MAX_SIGNED_LIMB, 0);
    debug_assert_eq!((ce as u64) & MAX_SIGNED_LIMB, 0);
    cd >>= SIGNED_LIMB_SIZE;
    ce >>= SIGNED_LIMB_SIZE;
    for i in 1..SIGNED_LIMBS - 1 {
        di = d.limbs[i];
        ei = e.limbs[i];
        cd += (u as i128) * (di as i128) + (v as i128) * (ei as i128);
        ce += (q as i128) * (di as i128) + (r as i128) * (ei as i128);
        d.limbs[i - 1] = ((cd as u64) & MAX_SIGNED_LIMB) as i64;
        cd >>= SIGNED_LIMB_SIZE;
        e.limbs[i - 1] = ((ce as u64) & MAX_SIGNED_LIMB) as i64;
        ce >>= SIGNED_LIMB_SIZE;
    }
    di = d.limbs[SIGNED_LIMBS - 1];
    ei = e.limbs[SIGNED_LIMBS - 1];
    cd += (u as i128) * (di as i128) + (v as i128) * (ei as i128);
    ce += (q as i128) * (di as i128) + (r as i128) * (ei as i128);
    cd += (md as i128) << FINAL_LIMB_MODULUS_BITS;
    ce += (me as i128) << FINAL_LIMB_MODULUS_BITS;
    d.limbs[SIGNED_LIMBS - 2] = ((cd as u64) & MAX_SIGNED_LIMB) as i64;
    cd >>= SIGNED_LIMB_SIZE;
    e.limbs[SIGNED_LIMBS - 2] = ((ce as u64) & MAX_SIGNED_LIMB) as i64;
    ce >>= SIGNED_LIMB_SIZE;
    d.limbs[SIGNED_LIMBS - 1] = cd as i64;
    e.limbs[SIGNED_LIMBS - 1] = ce as i64;
}

fn update_fg(f: &mut Signed, g: &mut Signed, t: &SignedMatrix, len: usize) {
    let (u, v, q, r) = (t.u, t.v, t.q, t.r);
    let mut fi = f.limbs[0];
    let mut gi = g.limbs[0];
    let mut cf: i128 = (u as i128) * (fi as i128) + (v as i128) * (gi as i128);
    let mut cg: i128 = (q as i128) * (fi as i128) + (r as i128) * (gi as i128);
    debug_assert_eq!((cf as u64) & MAX_SIGNED_LIMB, 0);
    debug_assert_eq!((cg as u64) & MAX_SIGNED_LIMB, 0);
    cf >>= SIGNED_LIMB_SIZE;
    cg >>= SIGNED_LIMB_SIZE;
    for i in 1..len {
        fi = f.limbs[i];
        gi = g.limbs[i];
        cf += (u as i128) * (fi as i128) + (v as i128) * (gi as i128);
        cg += (q as i128) * (fi as i128) + (r as i128) * (gi as i128);
        f.limbs[i - 1] = ((cf as u64) & MAX_SIGNED_LIMB) as i64;
        cf >>= SIGNED_LIMB_SIZE;
        g.limbs[i - 1] = ((cg as u64) & MAX_SIGNED_LIMB) as i64;
        cg >>= SIGNED_LIMB_SIZE;
    }
    f.limbs[len - 1] = cf as i64;
    g.limbs[len - 1] = cg as i64;
}

/// A multiset accumulator: numerator / denominator.
#[derive(Clone, Debug)]
pub(crate) struct MuHash {
    numerator: Num3072,
    denominator: Num3072,
}

impl Default for MuHash {
    fn default() -> Self {
        Self::new()
    }
}

impl MuHash {
    /// The empty set.
    pub(crate) fn new() -> Self {
        Self {
            numerator: Num3072::one(),
            denominator: Num3072::one(),
        }
    }

    /// A one-element set, as Core's `MuHash3072(span)` constructor.
    #[cfg(test)]
    pub(crate) fn from_element(element: &[u8]) -> Self {
        let mut set = Self::new();
        set.insert(element);
        set
    }

    /// A set whose accumulated numerator is already known (a stored value).
    pub(crate) fn from_numerator(numerator: Num3072) -> Self {
        Self {
            numerator,
            denominator: Num3072::one(),
        }
    }

    pub(crate) fn insert(&mut self, element: &[u8]) {
        self.insert_key(&Sha256::digest(element).into());
    }

    pub(crate) fn remove(&mut self, element: &[u8]) {
        self.remove_key(&Sha256::digest(element).into());
    }

    /// Insert an element already reduced to its SHA-256 key.
    pub(crate) fn insert_key(&mut self, key: &[u8; 32]) {
        self.numerator.multiply(&Num3072::from_key(key));
    }

    pub(crate) fn remove_key(&mut self, key: &[u8; 32]) {
        self.denominator.multiply(&Num3072::from_key(key));
    }

    /// self *= other (set union, multiplicities add).
    pub(crate) fn combine(&mut self, other: &MuHash) {
        self.numerator.multiply(&other.numerator);
        self.denominator.multiply(&other.denominator);
    }

    /// self /= other (set difference): the cross terms are multiplied, so the
    /// whole expression still needs only one inversion, at normalisation.
    pub(crate) fn uncombine(&mut self, other: &MuHash) {
        self.numerator.multiply(&other.denominator);
        self.denominator.multiply(&other.numerator);
    }

    /// Fold the denominator into the numerator with a single inversion and
    /// return the fully reduced value as 384 little-endian bytes.
    pub(crate) fn normalise(&mut self) -> [u8; BYTE_SIZE] {
        let denominator = std::mem::replace(&mut self.denominator, Num3072::one());
        self.numerator.divide(&denominator);
        self.numerator.to_le_bytes()
    }

    /// `SHA256` of the normalised 384-byte value (Core's `Finalize`).
    pub(crate) fn finalize(&mut self) -> [u8; 32] {
        Sha256::digest(self.normalise()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    fn modulus() -> BigUint {
        (BigUint::from(1_u8) << 3072_u32) - BigUint::from(MAX_PRIME_DIFF)
    }

    /// Core's `FromInt`: a one-element set over the 32 bytes {i, 0, ...}.
    fn from_int(i: u8) -> MuHash {
        let mut bytes = [0_u8; 32];
        bytes[0] = i;
        MuHash::from_element(&bytes)
    }

    fn reversed_hex(digest: [u8; 32]) -> String {
        let mut digest = digest;
        digest.reverse();
        hex::encode(digest)
    }

    /// Bitcoin Core v30.0 `crypto_tests.cpp` / `muhash.py`: the same value
    /// whether the third element is divided out or removed.
    #[test]
    fn core_vectors_multiply_divide_insert_remove() {
        const EXPECTED: &str = "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863";
        let mut acc = from_int(0);
        acc.combine(&from_int(1));
        acc.uncombine(&from_int(2));
        assert_eq!(reversed_hex(acc.finalize()), EXPECTED);

        let mut acc2 = from_int(0);
        let mut one = [0_u8; 32];
        one[0] = 1;
        let mut two = [0_u8; 32];
        two[0] = 2;
        acc2.insert(&one);
        acc2.remove(&two);
        assert_eq!(reversed_hex(acc2.finalize()), EXPECTED);
    }

    /// Core's overflow vector: a numerator of 2^3072 - 1 (>= p) with a
    /// denominator of 1 normalises to 1103716.
    #[test]
    fn core_vector_overflowing_numerator() {
        let mut set = MuHash::from_numerator(Num3072::from_le_bytes(&[0xff; BYTE_SIZE]));
        assert_eq!(
            hex::encode(set.finalize()),
            "3a31e6903aff0de9f62f9a9f7f8b861de76ce2cda09822b90014319ae5dc2271"
        );
        let mut set = MuHash::from_numerator(Num3072::from_le_bytes(&[0xff; BYTE_SIZE]));
        let value = BigUint::from_bytes_le(&set.normalise());
        assert_eq!(value, BigUint::from(MAX_PRIME_DIFF - 1));
    }

    /// Core's randomised order test, deterministic: every order of four
    /// multiplications and divisions finalises the same, and x*y/(y*x) is 1.
    #[test]
    fn core_order_independence_and_cancellation() {
        let table = [3_u8, 5, 1, 6];
        let mut results = Vec::new();
        for order in 0..4_usize {
            let mut acc = MuHash::new();
            for i in 0..4_usize {
                let t = table[i ^ order];
                if t & 4 != 0 {
                    acc.uncombine(&from_int(t & 3));
                } else {
                    acc.combine(&from_int(t & 3));
                }
            }
            results.push(acc.finalize());
        }
        assert!(results.windows(2).all(|pair| pair[0] == pair[1]));
        let (x, y) = (from_int(9), from_int(14));
        let mut z = MuHash::new();
        z.combine(&x);
        z.combine(&y);
        let mut yx = y.clone();
        yx.combine(&x);
        z.uncombine(&yx);
        assert_eq!(z.finalize(), MuHash::new().finalize());
    }

    fn random_key(state: &mut u64) -> [u8; 32] {
        let mut key = [0_u8; 32];
        for chunk in key.chunks_mut(8) {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            chunk.copy_from_slice(&state.to_le_bytes());
        }
        key
    }

    fn reduced(num: &Num3072) -> BigUint {
        BigUint::from_bytes_le(&num.to_le_bytes()) % modulus()
    }

    /// The fixed-width multiply and the safegcd inverse against num-bigint.
    #[test]
    fn fixed_width_arithmetic_matches_an_independent_bigint_oracle() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let p = modulus();
        let mut acc = Num3072::from_key(&random_key(&mut state));
        let mut expect = reduced(&acc);
        for _ in 0..40 {
            let next = Num3072::from_key(&random_key(&mut state));
            acc.multiply(&next);
            expect = (expect * reduced(&next)) % &p;
            assert_eq!(reduced(&acc), expect);
        }
        for _ in 0..8 {
            // The inverse takes a fully reduced input.
            let canonical = reduced(&Num3072::from_key(&random_key(&mut state)));
            let mut bytes = canonical.to_bytes_le();
            bytes.resize(BYTE_SIZE, 0);
            let x = Num3072::from_le_bytes(bytes.as_slice().try_into().unwrap());
            let inverse = x.inverse();
            let oracle = canonical.modinv(&p).expect("p is prime");
            assert_eq!(BigUint::from_bytes_le(&inverse.to_le_bytes()), oracle);
            let mut product = x.clone();
            product.multiply(&inverse);
            assert_eq!(reduced(&product), BigUint::from(1_u8));
        }
    }

    /// Values at every edge of the lazy-reduction range [0, 2^3072).
    fn boundary_values() -> Vec<(&'static str, BigUint)> {
        let p = modulus();
        let max = (BigUint::from(1_u8) << 3072_u32) - BigUint::from(1_u8);
        vec![
            ("0", BigUint::from(0_u8)),
            ("1", BigUint::from(1_u8)),
            ("p-1", &p - BigUint::from(1_u8)),
            ("p", p.clone()),
            ("p+1", &p + BigUint::from(1_u8)),
            ("2^3072-1", max),
        ]
    }

    fn num(value: &BigUint) -> Num3072 {
        let mut bytes = value.to_bytes_le();
        bytes.resize(BYTE_SIZE, 0);
        Num3072::from_le_bytes(bytes.as_slice().try_into().unwrap())
    }

    /// Multiply and normalise at 0, 1, p-1, p, p+1 and 2^3072-1 (every pair),
    /// against the oracle.
    #[test]
    fn reduction_boundaries_multiply_and_normalise() {
        let p = modulus();
        for (an, a) in boundary_values() {
            // Normalising alone reduces to the canonical representative.
            let mut set = MuHash::from_numerator(num(&a));
            assert_eq!(
                BigUint::from_bytes_le(&set.normalise()),
                &a % &p,
                "norm {an}"
            );
            for (bn, b) in boundary_values() {
                let mut product = num(&a);
                product.multiply(&num(&b));
                assert_eq!(reduced(&product), (&a * &b) % &p, "{an} * {bn}");
                // A numerator times a denominator whose residue is non-zero.
                if &b % &p != BigUint::from(0_u8) {
                    let mut set = MuHash::from_numerator(num(&a));
                    set.uncombine(&MuHash::from_numerator(num(&b)));
                    let expect = (&a % &p) * (&b % &p).modinv(&p).unwrap() % &p;
                    assert_eq!(
                        BigUint::from_bytes_le(&set.normalise()),
                        expect,
                        "{an} / {bn}"
                    );
                }
            }
        }
    }

    /// Inverses of reduced values at both ends of the range.
    #[test]
    fn inverses_near_the_boundaries() {
        let p = modulus();
        let one = BigUint::from(1_u8);
        let values = [
            one.clone(),
            BigUint::from(2_u8),
            BigUint::from(MAX_PRIME_DIFF - 1),
            BigUint::from(MAX_PRIME_DIFF),
            BigUint::from(MAX_PRIME_DIFF + 1),
            &p - BigUint::from(MAX_PRIME_DIFF),
            &p - BigUint::from(2_u8),
            &p - &one,
            (BigUint::from(1_u8) << 3071_u32) - &one,
            BigUint::from(1_u8) << 3071_u32,
        ];
        for value in values {
            let inverse = num(&value).inverse();
            assert_eq!(
                BigUint::from_bytes_le(&inverse.to_le_bytes()),
                value.modinv(&p).unwrap(),
                "inverse of {value}"
            );
        }
    }

    /// Inserting in any order gives the same digest.
    #[test]
    fn insertion_order_does_not_matter() {
        let mut state = 7_u64;
        let keys: Vec<[u8; 32]> = (0..64).map(|_| random_key(&mut state)).collect();
        let mut forward = MuHash::new();
        keys.iter().for_each(|key| forward.insert_key(key));
        let mut shuffled = keys.clone();
        for i in (1..shuffled.len()).rev() {
            let j = (random_key(&mut state)[0] as usize) % (i + 1);
            shuffled.swap(i, j);
        }
        let mut other = MuHash::new();
        shuffled.iter().for_each(|key| other.insert_key(key));
        assert_eq!(forward.finalize(), other.finalize());
    }
}
