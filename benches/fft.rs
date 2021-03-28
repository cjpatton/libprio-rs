// SPDX-License-Identifier: MPL-2.0

use criterion::{criterion_group, criterion_main, Criterion};
use prio::fft;
use prio::finite_field::{Field, FieldElement};
use prio::polynomial;

pub fn fft(c: &mut Criterion) {
    let test_sizes = [16, 256, 1024, 4096];
    for size in test_sizes.iter() {
        let mut rng = rand::thread_rng();
        let mut inp = vec![Field::zero(); *size];
        let mut outp = vec![Field::zero(); *size];
        for i in 0..*size {
            inp[i] = Field::rand(&mut rng);
        }

        // Test recursive FFT, including auxiliary data computation.
        c.bench_function(&format!("recursive/{}", *size), |b| {
            b.iter(|| {
                let mut mem = polynomial::PolyAuxMemory::new(*size / 2);
                polynomial::poly_fft(
                    &mut outp,
                    &inp,
                    &mem.roots_2n,
                    *size,
                    false,
                    &mut mem.fft_memory,
                )
            })
        });

        // Test recursive FFT, but amortize auxiliary data computation across all of the
        // invocations of the call.
        let mut mem = polynomial::PolyAuxMemory::new(*size / 2);
        c.bench_function(&format!("recursive/{} (amortized)", *size), |b| {
            b.iter(|| {
                polynomial::poly_fft(
                    &mut outp,
                    &inp,
                    &mem.roots_2n,
                    *size,
                    false,
                    &mut mem.fft_memory,
                )
            })
        });

        // Test iteratigve FFT.
        c.bench_function(&format!("iterative/{}", *size), |b| {
            b.iter(|| fft::discrete_fourier_transform::<Field>(&mut outp, &inp))
        });
    }
}

criterion_group!(benches, fft);
criterion_main!(benches);
