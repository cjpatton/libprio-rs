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

use crate::field::FieldElement;

/// This type represents an input to be validated.
pub trait Datum<F: FieldElement, G: Gadget<F>>: Sized {
    /// Evalauates the arithmetic circuit on the given input (i.e., `self`) and returns the output.
    /// `rand` is the random input of the validity circuit.
    fn valid(&self, rand: &[F]) -> F;

    /// Returns an instance of gadget associated with the validity circuit. The length of the proof
    /// generated for this data type is linear in the number of times the gadget is invoked.
    fn gadget(&self) -> G;

    /// Returns a reference to the input encoded as a vector of field elements.
    fn vec(&self) -> &[F];

    /// Tries to construct an instance of this type from a vector of field Elements. Returns `None`
    /// if the input is not the correct length.
    fn from_vec(vec: &[F]) -> Option<Self>;
}

/// The sub-circuit associated with some validity circuit.
pub trait Gadget<F: FieldElement> {
    /// Evaluates the gadget on input `inp` and returns the output.
    fn call(&self, inp: &[F]) -> F;
}

/// Generate a PCP of the validity of `x`'. This is algorithm is run by the prover.
pub fn prove<F: FieldElement, G: Gadget<F>, T: Datum<F, G>>(x: &T) -> Proof<F> {
    // XXX
    panic!("TODO");
}

/// The output of `prove`.
pub struct Proof<F: FieldElement> {
    // XXX
    phantom: PhantomData<F>,
}

/// Generate the verification message for input `x` and proof `pf`, and randomness `rand`. This
/// algorithm is run by the verifier. In Prio, each aggregator runs this algorithm on a share of
/// the proof and input.
pub fn query<F: FieldElement, G: Gadget<F>, T: Datum<F, G>>(
    x: &T,
    pf: &Proof<F>,
    rand: &[F],
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
pub fn decide<F: FieldElement, G: Gadget<F>, T: Datum<F, G>>(x: &T, vf: &Verifier<F>) -> bool {
    // XXX
    panic!("TODO");
}
