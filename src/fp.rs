// Copyright (c) 2021 The Authors
// SPDX-License-Identifier: MPL-2.0

use rand::prelude::*;
use rand::Rng;

// Parameters of a finite field with prime p < 2^126. Field elements are represented as u128's.
pub struct Fp {
    pub p: u128,  // the prime modulus p
    pub mu: u64,  // mu = -p^(-1) mod 2^64
    pub r2: u128, // r2 = (2^128)^2 mod p
}

impl Fp {
    pub fn add(&self, x: u128, y: u128) -> u128 {
        let z = x.wrapping_add(y).wrapping_sub(self.p << 1);
        z.wrapping_add(mask(x, y, z) & self.p << 1)
    }

    pub fn sub(&self, x: u128, y: u128) -> u128 {
        let z = x.wrapping_sub(y);
        z.wrapping_add(mask(x, y, z) & self.p << 1)
    }

    pub fn mul(&self, x: u128, y: u128) -> u128 {
        // NOTE(cjpatton): This multiplication algorithm was ported diretly from XXX, which
        // represaents field elements as a pair of 64-bit integers. Can we write a more efficient
        // algorithm that takes adavantage of Rust's ability to represent 128-bit integers
        // natively?
        let x = [lo64(x), hi64(x)];
        let y = [lo64(y), hi64(y)];
        let p = [lo64(self.p), hi64(self.p)];
        let mut zz = [0; 4];
        let mut result: (u64, u64);
        let mut carry: u64;
        let mut hi: u64;
        let mut lo: u64;
        let mut cc: u64;

        // Integer multiplication
        result = mul64(x[0], y[0]);
        carry = result.0;
        zz[0] = result.1;
        result = mul64(x[0], y[1]);
        hi = result.0;
        lo = result.1;
        result = add64(lo, carry, 0);
        zz[1] = result.0;
        cc = result.1;
        result = add64(hi, 0, cc);
        zz[2] = result.0;

        result = mul64(x[1], y[0]);
        hi = result.0;
        lo = result.1;
        result = add64(zz[1], lo, 0);
        zz[1] = result.0;
        cc = result.1;
        result = add64(hi, 0, cc);
        carry = result.0;

        result = mul64(x[1], y[1]);
        hi = result.0;
        lo = result.1;
        result = add64(lo, carry, 0);
        lo = result.0;
        cc = result.1;
        result = add64(hi, 0, cc);
        hi = result.0;
        result = add64(zz[2], lo, 0);
        zz[2] = result.0;
        cc = result.1;
        result = add64(hi, 0, cc);
        zz[3] = result.0;

        // Reduction
        let w = self.mu.wrapping_mul(zz[0]);
        result = mul64(p[0], w);
        hi = result.0;
        lo = result.1;
        result = add64(zz[0], lo, 0);
        zz[0] = result.0;
        cc = result.1;
        result = add64(hi, 0, cc);
        carry = result.0;

        result = mul64(p[1], w);
        hi = result.0;
        lo = result.1;
        result = add64(lo, carry, 0);
        lo = result.0;
        cc = result.1;
        result = add64(hi, 0, cc);
        hi = result.0;
        result = add64(zz[1], lo, 0);
        zz[1] = result.0;
        cc = result.1;
        result = add64(zz[2], hi, cc);
        zz[2] = result.0;
        cc = result.1;
        result = add64(zz[3], 0, cc);
        zz[3] = result.0;

        let w = self.mu.wrapping_mul(zz[1]);
        result = mul64(p[0], w);
        hi = result.0;
        lo = result.1;
        result = add64(zz[1], lo, 0);
        zz[1] = result.0;
        cc = result.1;
        result = add64(hi, 0, cc);
        carry = result.0;

        result = mul64(p[1], w);
        hi = result.0;
        lo = result.1;
        result = add64(lo, carry, 0);
        lo = result.0;
        cc = result.1;
        result = add64(hi, 0, cc);
        hi = result.0;
        result = add64(zz[2], lo, 0);
        zz[2] = result.0;
        cc = result.1;
        result = add64(zz[3], hi, cc);
        zz[3] = result.0;

        (zz[2] as u128) | ((zz[3] as u128) << 64)
    }

    pub fn pow(&self, x: u128, exp: u128) -> u128 {
        let mut t = self.elem(1);
        for i in (0..128).rev() {
            t = self.mul(t, t);
            if (exp >> i) & 1 != 0 {
                t = self.mul(t, x);
            }
        }
        t
    }

    pub fn inv(&self, x: u128) -> u128 {
        self.pow(x, self.p - 2)
    }

    pub fn neg(&self, x: u128) -> u128 {
        self.sub(self.elem(0), x)
    }

    pub fn elem(&self, x: u128) -> u128 {
        modp(self.mul(x, self.r2), self.p)
    }

    pub fn rand_elem<R: Rng + ?Sized>(&self, rng: &mut R) -> u128 {
        let uniform = rand::distributions::Uniform::from(0..self.p);
        self.elem(uniform.sample(rng))
    }

    pub fn from_elem(&self, x: u128) -> u128 {
        modp(self.mul(x, 1), self.p)
    }
}

fn lo64(x: u128) -> u64 {
    (x & ((1 << 64) - 1)) as u64
}

fn hi64(x: u128) -> u64 {
    (x >> 64) as u64
}

fn add64(x: u64, y: u64, carry: u64) -> (u64, u64) {
    let sum = x.wrapping_add(y).wrapping_add(carry);
    let carry_out = ((x & y) | ((x | y) & !sum)) >> 63;
    (sum, carry_out)
}

fn mul64(x: u64, y: u64) -> (u64, u64) {
    let z = (x as u128) * (y as u128);
    (hi64(z), lo64(z))
}

// mask computes an intermediate value used in modular reduction. The output is (1<<128)-1 if the
// top bit of x is 0 and the top bit of y is 1 or if they are the same and the top bit of z is set.
// Otherwise, the output is 0.
fn mask(x: u128, y: u128, z: u128) -> u128 {
    let c = ((!x & y) | (!(x ^ y) & z)) >> 127;
    0u128.wrapping_sub(c)
}

fn modp(x: u128, p: u128) -> u128 {
    let z = x.wrapping_sub(p);
    z.wrapping_add(mask(x, p, z) & p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use modinverse::modinverse;
    use num_bigint::{BigInt, ToBigInt};

    #[test]
    fn test_fp() {
        let mut rng = rand::thread_rng();
        let test_fps = vec![
            Fp {
                p: 4293918721, // 32-bit prime
                mu: 17302828673139736575,
                r2: 1676699750,
            },
            Fp {
                p: 15564440312192434177, // 64-bit prime
                mu: 15564440312192434175,
                r2: 13031533328350459868,
            },
            Fp {
                p: 779190469673491460259841, // 80-bit prime
                mu: 18446744073709551615,
                r2: 699883506621195336351723,
            },
            Fp {
                p: 74769074762901517850839147140769382401, // 126-bit prime
                mu: 18446744073709551615,
                r2: 27801541991839173768379182336352451464,
            },
        ];

        for fp in test_fps.into_iter() {
            let big_p = &fp.p.to_bigint().unwrap();
            for _ in 0..100 {
                let x = fp.rand_elem(&mut rng);
                let y = fp.rand_elem(&mut rng);
                let big_x = &fp.from_elem(x).to_bigint().unwrap();
                let big_y = &fp.from_elem(y).to_bigint().unwrap();

                // Test addition.
                let got = fp.add(x, y);
                let want = (big_x + big_y) % big_p;
                assert_eq!(fp.from_elem(got).to_bigint().unwrap(), want);

                // Test subtraction.
                let got = fp.sub(x, y);
                let want = if big_x >= big_y {
                    big_x - big_y
                } else {
                    big_p - big_y + big_x
                };
                assert_eq!(fp.from_elem(got).to_bigint().unwrap(), want);

                // Test multiplication.
                let got = fp.mul(x, y);
                let want = (big_x * big_y) % big_p;
                assert_eq!(fp.from_elem(got).to_bigint().unwrap(), want);

                // Test inversion.
                let got = fp.inv(x);
                let want = modinverse(fp.from_elem(x) as i128, fp.p as i128).unwrap();
                assert_eq!(fp.from_elem(got) as i128, want);
                assert_eq!(fp.from_elem(fp.mul(got, x)), 1);

                // Test negation.
                let got = fp.neg(x);
                let want = (-(fp.from_elem(x) as i128)).rem_euclid(fp.p as i128);
                assert_eq!(fp.from_elem(got) as i128, want);
                assert_eq!(fp.from_elem(fp.add(got, x)), 0);
            }
        }
    }

    #[test]
    fn test_generate_fp() {
        let fp = generate_fp(15564440312192434177).expect("failed to generate parameters");
        assert_eq!(fp.p, 15564440312192434177);
        assert_eq!(fp.mu, 15564440312192434175);
        assert_eq!(fp.r2, 13031533328350459868);
    }

    fn generate_fp(p: u128) -> Result<Fp, &'static str> {
        let err_modulus_too_large = "p > 2^126";
        if let Some(x) = p.checked_next_power_of_two() {
            if x > 1 << 126 {
                return Err(err_modulus_too_large);
            }
        } else {
            return Err(err_modulus_too_large);
        }

        let mu = match modinverse((-(p as i128)).rem_euclid(1 << 64), 1 << 64) {
            Some(mu) => mu as u64,
            None => return Err("inverse of -p (mod 2^64) is undefined"),
        };

        let big_p = &p.to_bigint().unwrap();
        let big_r: &BigInt = &(&(BigInt::from(1) << 128) % big_p);
        let big_r2: &BigInt = &(&(big_r * big_r) % big_p);
        let mut it = big_r2.iter_u64_digits();
        let mut r2 = 0;
        r2 |= it.next().unwrap() as u128;
        if let Some(x) = it.next() {
            r2 |= (x as u128) << 64;
        }

        Ok(Fp { p, mu, r2 })
    }
}
