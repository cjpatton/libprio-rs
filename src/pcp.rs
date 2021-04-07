// SPDX-License-Identifier: MPL-2.0

//! This module implements the fully linear PCP ("Probabilistically Checkable Proof") system
//! decsribed in [[BBG+19](https://eprint.iacr.org/2021/017), Theorem 4.3]. It is the core
//! component of Prio's input-validation protocol.
//!
//! A PCP asserts that a given input is a member of a formal language, e.g., that each integer in
//! an input vector is within a certain range. The proof system is comprised of a proover and a
//! verifier. The prover generates a PCP for its input, and the verifier checks the PCP to
//! determine if the input is valid. This procedure should always succeed when the input is valid;
//! if the input is invalid, then the validatin procedure should fail, except with small
//! probability.
//!
//! A "fully linear" PCP system is a PCP system that can operate on secret shared data. In this
//! setting, the prover splits its input and proof into shares and distributes the shares among a
//! set of verifiers. Th verifiers then run a protocol in which they learn whether the input is
//! valid, but without learning the input itself.
//!
//! The fully linear PCP system of [BBG+19, Theorem 4.3] applies languages recognized by arithmetic
//! circuits over finite fields that have a particular structure. Namely, all gates in the circuit
//! are either affine (i.e., addition or scalar multiplication) or invoke a special sub-circuit,
//! called the gadget, which may contain non-affice operations (i.e., multiplication).

use std::marker::PhantomData;

use crate::fft::FftError;
use crate::field::FieldElement;
use crate::fp::log2;

/// Possible errors from finite field operations.
#[derive(Debug, thiserror::Error)]
pub enum PcpError {
    /// The the caller of an arithmetic circuite provided the wrong number of inputs.
    #[error("wrong number of inputs to arithmetic circuit")]
    CircuitInLen,
    /// XXX
    #[error("XXX")]
    CircuitInDeg,
    /// XXX
    #[error("XXX")]
    CircuitOutDeg,
    /// XXX
    #[error("FFT error")]
    Fft(#[from] FftError),
}

/// This type represents an input to be validated.
pub trait Datum<F: FieldElement, G: Gadget<F>>: Sized {
    /// Evalauates the arithmetic circuit on the given input (i.e., `self`) and returns the output.
    /// `rand` is the random input of the validity circuit.
    fn valid(&self, g: &mut dyn Gadget<F>, rand: &[F]) -> F;

    /// Returns an instance of gadget associated with the validity circuit. The length of the proof
    /// generated for this data type is linear in the number of times the gadget is invoked.
    fn gadget(&self) -> G
    where
        G: GadgetWithCallPoly<F>;

    /// XXX
    fn gadget_call_ct(&self) -> usize;

    /// Returns a reference to the input encoded as a vector of field elements.
    fn vec(&self) -> &[F];

    /// Tries to construct an instance of this type from a vector of field Elements. Returns `None`
    /// if the input is not the correct length.
    fn from_vec(vec: &[F]) -> Option<Self>;
}

/// The sub-circuit associated with some validity circuit.
pub trait Gadget<F: FieldElement> {
    /// Evaluates the gadget on input `inp` and returns the output.
    fn call(&mut self, inp: &[F]) -> Result<F, PcpError>;

    /// XXX
    fn call_in_len(&self) -> usize;
}

/// XXX
pub trait GadgetWithCallPoly<F: FieldElement> {
    /// Evaluate the gaget on input of a sequence of polynomials `inp` over `F`.
    fn call_poly<V: AsRef<[F]>>(&mut self, outp: &mut [F], inp: &[V]) -> Result<(), PcpError>;

    /// XXX
    fn call_poly_out_deg(&self, in_deg: usize) -> usize;
}

/// Generate a PCP of the validity of `x`'. This is algorithm is run by the prover.
pub fn prove<F: FieldElement, G: Gadget<F>, T: Datum<F, G>>(x: &T) -> Proof<F>
where
    G: GadgetWithCallPoly<F>,
{
    let g = x.gadget();
    let m = 1 << log2(x.gadget_call_ct() as u128 + 1);
    let l = g.call_in_len();
    panic!("TODO");
}

/// The output of `prove`.
pub struct Proof<F: FieldElement> {
    /// The first coefficient of each intermediate proof polynomial.
    pub f0: Vec<F>,
    /// The proof polynomial.
    pub p: Vec<F>,
}

/// Generate the verification message for input `x` and proof `pf`, and randomness `rand`. This
/// algorithm is run by the verifier. In Prio, each aggregator runs this algorithm on a share of
/// the proof and input.
pub fn query<F: FieldElement, G: Gadget<F>, T: Datum<F, G>>(
    _x: &T,
    _pf: &Proof<F>,
    _rand: &[F],
) -> Verifier<F> {
    // XXX
    panic!("TODO");
}

/// The output of `query`.
pub struct Verifier<F: FieldElement> {
    // XXX
    phantom: PhantomData<F>,
}

/// Decide if input `x` is valid based on verification message `vf`. This algorithm is run by the
/// verifier. IN prio, this algorithm is run by the leader and the output is distributed among the
/// rest of the aggregators.
pub fn decide<F: FieldElement, G: Gadget<F>, T: Datum<F, G>>(_x: &T, _vf: &Verifier<F>) -> bool {
    // XXX
    panic!("TODO");
}

pub mod datum {
    //! A collection of data types.
    use super::gadget::MulGadget;
    use super::*;

    /// XXX
    pub struct Bool<F: FieldElement> {
        data: [F; 1],
    }

    impl<F: FieldElement> Bool<F> {
        pub fn new(b: bool) -> Self {
            let val = match b {
                true => F::root(0).unwrap(),
                false => F::zero(),
            };
            Self { data: [val] }
        }
    }

    impl<F: FieldElement> Datum<F, MulGadget<F>> for Bool<F> {
        fn valid(&self, g: &mut dyn Gadget<F>, rand: &[F]) -> F {
            panic!("TODO");
        }

        fn gadget(&self) -> MulGadget<F> {
            panic!("TODO");
        }

        fn gadget_call_ct(&self) -> usize {
            panic!("TODO");
        }

        fn vec(&self) -> &[F] {
            panic!("TODO");
        }

        fn from_vec(vec: &[F]) -> Option<Self> {
            panic!("TODO");
        }
    }
}

pub mod gadget {
    //! A collection of gadgets.
    use super::*;
    use crate::fft::{discrete_fourier_transform, discrete_fourier_transform_inv};

    /// An arity-2 gadget that multiples the inputs.
    pub struct MulGadget<F: FieldElement>(PhantomData<F>);

    impl<F: FieldElement> MulGadget<F> {
        /// XXX
        pub fn new() -> Self {
            Self(PhantomData)
        }
    }

    impl<F: FieldElement> Gadget<F> for MulGadget<F> {
        fn call(&mut self, inp: &[F]) -> Result<F, PcpError> {
            gadget_call_check(self, inp)?;
            Ok(inp[0] * inp[1])
        }

        fn call_in_len(&self) -> usize {
            2
        }
    }

    impl<F: FieldElement> GadgetWithCallPoly<F> for MulGadget<F> {
        fn call_poly<V: AsRef<[F]>>(&mut self, outp: &mut [F], inp: &[V]) -> Result<(), PcpError> {
            gadget_call_poly_check(self, outp, inp)?;
            let n = 2 * inp[0].as_ref().len();
            let mut buf = vec![F::zero(); n];

            discrete_fourier_transform(&mut buf, inp[0].as_ref(), n)?;
            discrete_fourier_transform(outp, inp[1].as_ref(), n)?;

            for i in 0..n {
                buf[i] *= outp[i];
            }

            discrete_fourier_transform_inv(outp, &buf, n)?;
            Ok(())
        }

        fn call_poly_out_deg(&self, in_deg: usize) -> usize {
            2 * in_deg
        }
    }

    // Check that the input parameters of g.call() are wll-formed.
    fn gadget_call_check<F: FieldElement, G: Gadget<F>>(g: &G, inp: &[F]) -> Result<(), PcpError> {
        if inp.len() != g.call_in_len() {
            return Err(PcpError::CircuitInLen);
        }

        Ok(())
    }

    // Check that the input parameters of g.call_poly() are well-formed.
    fn gadget_call_poly_check<F: FieldElement, G: Gadget<F>, V: AsRef<[F]>>(
        g: &G,
        outp: &[F],
        inp: &[V],
    ) -> Result<(), PcpError>
    where
        G: GadgetWithCallPoly<F>,
    {
        if inp.len() != g.call_in_len() {
            return Err(PcpError::CircuitInLen);
        }

        if inp.len() == 0 {
            return Ok(());
        }

        for i in 1..inp.len() {
            if inp[i].as_ref().len() != inp[0].as_ref().len() {
                return Err(PcpError::CircuitInDeg);
            }
        }

        if outp.len() < g.call_poly_out_deg(inp[0].as_ref().len()) {
            return Err(PcpError::CircuitOutDeg);
        }

        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        use crate::field::Field80 as TestField;
        use crate::polynomial::poly_eval;

        // Test that calling g.call_poly() and evaluating the output at a given point is equivalent
        // to evaluating each of the inputs at the same point and aplying g.call() on the results.
        fn gadget_test<F: FieldElement, G: Gadget<F>>(g: &mut G)
        where
            G: GadgetWithCallPoly<F>,
        {
            let poly_in_deg = 128;
            let mut rng = rand::thread_rng();
            let mut inp = vec![F::zero(); g.call_in_len()];
            let mut poly_outp = vec![F::zero(); g.call_poly_out_deg(poly_in_deg)];
            let mut poly_inp = vec![vec![F::zero(); poly_in_deg]; g.call_in_len()];

            let r = F::rand(&mut rng);
            for i in 0..g.call_in_len() {
                for j in 0..poly_in_deg {
                    poly_inp[i][j] = F::rand(&mut rng);
                }
                inp[i] = poly_eval(&poly_inp[i], r);
            }

            g.call_poly(&mut poly_outp, &poly_inp).unwrap();
            let got = poly_eval(&poly_outp, r);
            let want = g.call(&inp).unwrap();
            assert_eq!(got, want);
        }

        #[test]
        fn test_mul_gadget() {
            let mut g: MulGadget<TestField> = MulGadget::new();
            gadget_test(&mut g);
        }
    }
}
