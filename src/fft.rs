// SPDX-License-Identifier: MPL-2.0

//! This module implements an iterative FFT algorithm for computing the (inverse) Discrete Fourier
//! Transform (DFT) over a slice of field elements.

use crate::field::FieldElement;
use crate::fp::{log2, MAX_ROOTS};

use std::convert::TryFrom;

/// An error returned by an FFT operation.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum FftError {
    /// The output is too small.
    #[error("output slice is smaller than specified size")]
    OutputTooSmall,
    /// The specified size is too large.
    #[error("size is larger than than maximum permitted")]
    SizeTooLarge,
    /// The specified size is not a power of 2.
    #[error("size is not a power of 2")]
    SizeInvalid,
}

/// Sets `outp` to the DFT of `inp`. Interpreting the input as the coefficients of a polynomial,
/// the output is equal to the input evaluated at points `p^0, p^1, ... p^(size-1)`, where `p` is
/// the `2^size`-th principal root of unity.
pub fn discrete_fourier_transform<F: FieldElement>(
    outp: &mut [F],
    inp: &[F],
    size: usize,
) -> Result<(), FftError> {
    let d = usize::try_from(log2(size as u128)).unwrap();

    if size > outp.len() {
        return Err(FftError::OutputTooSmall);
    }

    if size > 1 << MAX_ROOTS {
        return Err(FftError::SizeTooLarge);
    }

    if size != 1 << d {
        return Err(FftError::SizeInvalid);
    }

    for i in 0..size {
        let j = bitrev(d, i);
        if j < inp.len() {
            outp[i] = inp[j];
        } else {
            outp[i] = F::zero();
        }
    }

    let mut w: F;
    for l in 1..d + 1 {
        w = F::one();
        let r = F::root(l).unwrap();
        let y = 1 << (l - 1);
        for i in 0..y {
            for j in 0..(size / y) >> 1 {
                let x = (1 << l) * j + i;
                let u = outp[x];
                let v = w * outp[x + y];
                outp[x] = u + v;
                outp[x + y] = u - v;
            }
            w *= r;
        }
    }

    Ok(())
}

/// Sets `outp` to the inverse of the DFT of `inp`.
pub fn discrete_fourier_transform_inv<F: FieldElement>(
    outp: &mut [F],
    inp: &[F],
    size: usize,
) -> Result<(), FftError> {
    let size_inv = F::from(F::Integer::try_from(size).unwrap()).inv();
    discrete_fourier_transform(outp, inp, size)?;
    discrete_fourier_transform_inv_finish(outp, size, size_inv);
    Ok(())
}

/// An intermediate step in the computation of the inverse DFT. Exposing this function allows us to
/// amortize the cost the modular inverse across multiple inverse DFT operations.
pub(crate) fn discrete_fourier_transform_inv_finish<F: FieldElement>(
    outp: &mut [F],
    size: usize,
    size_inv: F,
) {
    let mut tmp: F;
    outp[0] *= size_inv;
    outp[size >> 1] *= size_inv;
    for i in 1..size >> 1 {
        tmp = outp[i] * size_inv;
        outp[i] = outp[size - i] * size_inv;
        outp[size - i] = tmp;
    }
}

// bitrev returns the first d bits of x in reverse order. (Thanks, OEIS! https://oeis.org/A030109)
fn bitrev(d: usize, x: usize) -> usize {
    let mut y = 0;
    for i in 0..d {
        y += ((x >> i) & 1) << (d - i);
    }
    y >> 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{Field126, Field32, Field64, Field80};
    use crate::polynomial::{poly_fft, PolyAuxMemory};

    fn discrete_fourier_transform_then_inv_test<F: FieldElement>() -> Result<(), FftError> {
        let test_sizes = [1, 2, 4, 8, 16, 256, 1024, 2048];

        for size in test_sizes.iter() {
            let mut want = vec![F::zero(); *size];
            let mut tmp = vec![F::zero(); *size];
            let mut got = vec![F::zero(); *size];
            for i in 0..*size {
                want[i] = F::rand();
            }

            discrete_fourier_transform(&mut tmp, &want, want.len())?;
            discrete_fourier_transform_inv(&mut got, &tmp, tmp.len())?;
            assert_eq!(got, want);
        }

        Ok(())
    }

    #[test]
    fn test_field32() {
        discrete_fourier_transform_then_inv_test::<Field32>().expect("unexpected error");
    }

    #[test]
    fn test_field64() {
        discrete_fourier_transform_then_inv_test::<Field64>().expect("unexpected error");
    }

    #[test]
    fn test_field80() {
        discrete_fourier_transform_then_inv_test::<Field80>().expect("unexpected error");
    }

    #[test]
    fn test_field126() {
        discrete_fourier_transform_then_inv_test::<Field126>().expect("unexpected error");
    }

    #[test]
    fn test_recursive_fft() {
        let size = 128;
        let mut mem = PolyAuxMemory::new(size / 2);

        let mut inp = vec![Field32::zero(); size];
        let mut want = vec![Field32::zero(); size];
        let mut got = vec![Field32::zero(); size];
        for i in 0..size {
            inp[i] = Field32::rand();
        }

        discrete_fourier_transform::<Field32>(&mut want, &inp, inp.len()).unwrap();

        poly_fft(
            &mut got,
            &inp,
            &mem.roots_2n,
            size,
            false,
            &mut mem.fft_memory,
        );

        assert_eq!(got, want);
    }

    #[test]
    fn test_fft_linearity() {
        use crate::field::{rand_vec, split};
        let len = 16;
        let num_shares = 11;
        let mut x: Vec<Field64> = rand_vec(len);
        let mut x_shares = split(&x, num_shares);

        for i in 0..len {
            if i % 2 != 0 {
                x_shares[0][i] = x[i]
            }
            for j in 1..num_shares {
                if i % 2 != 0 {
                    x_shares[j][i] = Field64::zero();
                }
            }
        }

        let mut got = vec![Field64::zero(); len];
        let mut buf = vec![Field64::zero(); len];
        for j in 0..num_shares {
            discrete_fourier_transform_inv(&mut buf, &x_shares[j], len).unwrap();
            for i in 0..len {
                got[i] += buf[i];
            }
        }

        let mut want = vec![Field64::zero(); len];
        discrete_fourier_transform_inv(&mut want, &x, len).unwrap();

        assert_eq!(got, want);
    }
}
