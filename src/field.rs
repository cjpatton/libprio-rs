// Copyright (c) 2020 Apple Inc.
// SPDX-License-Identifier: MPL-2.0

//! Finite field arithmetic.
//!
//! Basic field arithmetic is captured in the [`FieldElement`] trait. Fields used in Prio implement
//! [`NttFriendlyFieldElement`], and have an associated element called the "generator" that
//! generates a multiplicative subgroup of order `2^n` for some `n`.

use crate::{
    codec::{CodecError, Decode, Encode},
    fp::{FieldOps, FieldParameters, FP128, FP32, FP64},
    prng::Prng,
};
use rand::{
    distr::{Distribution, StandardUniform},
    Rng,
};
use rand_core::RngCore;
use serde::{
    de::{DeserializeOwned, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{
    cmp::min,
    convert::{TryFrom, TryInto},
    fmt::{self, Debug, Display, Formatter},
    hash::{Hash, Hasher},
    io::{Cursor, Read},
    marker::PhantomData,
    ops::{
        Add, AddAssign, BitAnd, ControlFlow, Div, DivAssign, Mul, MulAssign, Neg, Range, Shl, Shr,
        Sub, SubAssign,
    },
};
use subtle::{Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq};

#[cfg(feature = "experimental")]
mod field255;

#[cfg(feature = "experimental")]
pub use field255::Field255;

/// Possible errors from finite field operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FieldError {
    /// Input sizes do not match.
    #[error("input sizes do not match")]
    InputSizeMismatch,
    /// Returned when decoding a [`FieldElement`] from a too-short byte string.
    #[error("short read from bytes")]
    ShortRead,
    /// Returned when converting an integer to a [`FieldElement`] if the integer is greater than or
    /// equal to the field modulus.
    #[error("input value exceeds modulus")]
    ModulusOverflow,
    /// Error while performing I/O.
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    /// Error encoding or decoding a field.
    #[error("Codec error")]
    #[deprecated]
    Codec(CodecError),
    /// Error converting to [`FieldElementWithInteger::Integer`].
    #[error("Integer TryFrom error")]
    IntegerTryFrom,
    /// Returned when encoding an integer to "bitvector representation", or decoding from the same,
    /// if the number of bits is larger than the bit length of the field's modulus.
    #[error("bit vector length exceeds modulus bit length")]
    BitVectorTooLong,
}

/// Objects with this trait represent an element of `GF(p)` for some prime `p`.
pub trait FieldElement:
    Sized
    + Debug
    + Copy
    + PartialEq
    + Eq
    + ConstantTimeEq
    + ConditionallySelectable
    + ConditionallyNegatable
    + Add<Output = Self>
    + AddAssign
    + Sub<Output = Self>
    + SubAssign
    + Mul<Output = Self>
    + MulAssign
    + Div<Output = Self>
    + DivAssign
    + Neg<Output = Self>
    + Display
    + for<'a> TryFrom<&'a [u8], Error = FieldError>
    // NOTE Ideally we would require `Into<[u8; Self::ENCODED_SIZE]>` instead of `Into<Vec<u8>>`,
    // since the former avoids a heap allocation and can easily be converted into Vec<u8>, but that
    // isn't possible yet[1]. However we can provide the impl on FieldElement implementations.
    // [1]: https://github.com/rust-lang/rust/issues/60551
    + Into<Vec<u8>>
    + Serialize
    + DeserializeOwned
    + Encode
    + Decode
    + 'static // NOTE This bound is needed for downcasting a `dyn Gadget<F>>` to a concrete type.
{
    /// Size in bytes of an encoded field element.
    const ENCODED_SIZE: usize;

    /// Modular inversion, i.e., `self^-1 (mod p)`. If `self` is 0, then the output is undefined.
    fn inv(&self) -> Self;

    /// Interprets the next [`Self::ENCODED_SIZE`] bytes from the input slice as an element of the
    /// field. Any of the most significant bits beyond the bit length of the modulus will be
    /// cleared, in order to minimize the amount of rejection sampling needed.
    ///
    /// # Errors
    ///
    /// An error is returned if the provided slice is too small to encode a field element or if the
    /// result encodes an integer larger than or equal to the field modulus.
    ///
    /// # Warnings
    ///
    /// This function should only be used internally to convert a random byte string into
    /// a field element. Use [`Decode::decode`] to deserialize field elements. Use
    /// [`random_vector`] to randomly generate field elements.
    #[doc(hidden)]
    fn try_from_random(bytes: &[u8]) -> Result<Self, FieldError>;

    /// Returns the additive identity.
    fn zero() -> Self;

    /// Returns the multiplicative identity.
    fn one() -> Self;

    /// Convert a slice of field elements into a vector of bytes.
    ///
    /// # Notes
    ///
    /// Ideally we would implement `From<&[F: FieldElement]> for Vec<u8>` or the corresponding
    /// `Into`, but the orphan rule and the stdlib's blanket implementations of `Into` make this
    /// impossible.
    #[deprecated]
    fn slice_into_byte_vec(values: &[Self]) -> Vec<u8> {
        let mut vec = Vec::with_capacity(values.len() * Self::ENCODED_SIZE);
        encode_fieldvec(values, &mut vec).unwrap();
        vec
    }

    /// Convert a slice of bytes into a vector of field elements. The slice is interpreted as a
    /// sequence of [`Self::ENCODED_SIZE`]-byte sequences.
    ///
    /// # Errors
    ///
    /// Returns an error if the length of the provided byte slice is not a multiple of the size of a
    /// field element, or if any of the values in the byte slice are invalid encodings of a field
    /// element, because the encoded integer is larger than or equal to the field modulus.
    ///
    /// # Notes
    ///
    /// Ideally we would implement `From<&[u8]> for Vec<F: FieldElement>` or the corresponding
    /// `Into`, but the orphan rule and the stdlib's blanket implementations of `Into` make this
    /// impossible.
    #[deprecated]
    fn byte_slice_into_vec(bytes: &[u8]) -> Result<Vec<Self>, FieldError> {
        if bytes.len() % Self::ENCODED_SIZE != 0 {
            return Err(FieldError::ShortRead);
        }
        let mut vec = Vec::with_capacity(bytes.len() / Self::ENCODED_SIZE);
        for chunk in bytes.chunks_exact(Self::ENCODED_SIZE) {
            #[allow(deprecated)]
            vec.push(Self::get_decoded(chunk).map_err(FieldError::Codec)?);
        }
        Ok(vec)
    }

    /// Generate a vector of uniformly distributed random field elements.
    fn random_vector(len: usize) -> Vec<Self> {
        Prng::new().take(len).collect()
    }
}

/// An integer type that accompanies a finite field. Integers and field elements may be converted
/// back and forth via the natural map between residue classes modulo 'p' and integers between 0
/// and p - 1.
pub trait Integer:
    Debug
    + Eq
    + Ord
    + BitAnd<Output = Self>
    + Div<Output = Self>
    + Shl<usize, Output = Self>
    + Shr<usize, Output = Self>
    + Add<Output = Self>
    + Sub<Output = Self>
    + TryFrom<usize, Error = Self::TryFromUsizeError>
    + TryInto<u64, Error = Self::TryIntoU64Error>
{
    /// The error returned if converting `usize` to this integer type fails.
    type TryFromUsizeError: std::error::Error;

    /// The error returned if converting this integer type to a `u64` fails.
    type TryIntoU64Error: std::error::Error;

    /// Returns zero.
    fn zero() -> Self;

    /// Returns one.
    fn one() -> Self;

    /// Returns ⌊log₂(self)⌋, or `None` if `self == 0`
    fn checked_ilog2(&self) -> Option<u32>;
}

/// Extension trait for field elements that can be converted back and forth to an integer type.
///
/// The `Integer` associated type is an integer (primitive or otherwise) that supports various
/// arithmetic operations. The order of the field is guaranteed to fit inside the range of the
/// integer type. This trait also defines methods on field elements, `pow` and `modulus`, that make
/// use of the associated integer type.
pub trait FieldElementWithInteger: FieldElement + From<Self::Integer> {
    /// The integer representation of a field element.
    type Integer: Integer + From<Self> + Copy;

    /// Modular exponentation, i.e., `self^exp (mod p)`.
    fn pow(&self, exp: Self::Integer) -> Self;

    /// Returns the prime modulus `p`.
    fn modulus() -> Self::Integer;
    /// Encode the integer `input` as a sequence of bits in two's complement representation, least
    /// significant bit first, and then map each bit to a field element.
    ///
    /// Returns an error if `input` cannot be represented with `bits` many bits, or if `bits`
    /// is larger than the bit width of the field's modulus.
    fn encode_as_bitvector(
        input: Self::Integer,
        bits: usize,
    ) -> Result<BitvectorRepresentationIter<Self>, FieldError> {
        // Check if `bits` is too large for this field.
        if !Self::valid_integer_bitlength(bits) {
            return Err(FieldError::BitVectorTooLong);
        }

        // Check if the input value can be represented in the requested number of bits by shifting
        // it. The above check on `bits` ensures this shift won't panic due to the shift width
        // being too large.
        if input >> bits != Self::Integer::zero() {
            return Err(FieldError::InputSizeMismatch);
        }

        Ok(BitvectorRepresentationIter {
            inner: 0..bits,
            input,
        })
    }

    /// Inverts the encoding done by [`Self::encode_as_bitvector`], and returns a single field
    /// element.
    ///
    /// This performs an inner product between the input vector of field elements and successive
    /// powers of two (starting with 2^0 = 1). If the input came from [`Self::encode_as_bitvector`],
    /// then the result will be equal to the originally encoded integer, projected into the field.
    ///
    /// Note that this decoding operation is linear, so it can be applied to secret shares of an
    /// encoded integer, and if the results are summed up, it will be equal to the encoded integer.
    ///
    /// Returns an error if the length of the input is larger than the bit width of the field's
    /// modulus.
    fn decode_bitvector(input: &[Self]) -> Result<Self, FieldError> {
        if !Self::valid_integer_bitlength(input.len()) {
            return Err(FieldError::BitVectorTooLong);
        }

        let mut decoded = Self::zero();
        let one = Self::one();
        let two = one + one;
        let mut power_of_two = one;
        for value in input.iter() {
            decoded += *value * power_of_two;
            power_of_two *= two;
        }
        Ok(decoded)
    }
}

/// This iterator returns a sequence of field elements that are equal to zero or one, representing
/// some integer in two's complement form. See [`FieldElementWithInteger::encode_as_bitvector`].
// Note that this is implemented with a separate struct, instead of using the map combinator,
// because return_position_impl_trait_in_trait is not yet stable.
#[derive(Debug, Clone)]
pub struct BitvectorRepresentationIter<F: FieldElementWithInteger> {
    inner: Range<usize>,
    input: F::Integer,
}

impl<F> Iterator for BitvectorRepresentationIter<F>
where
    F: FieldElementWithInteger,
{
    type Item = F;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let bit_offset = self.inner.next()?;
        Some(F::from((self.input >> bit_offset) & F::Integer::one()))
    }
}

/// Methods common to all `FieldElementWithInteger` implementations that are private to the crate.
pub(crate) trait FieldElementWithIntegerExt: FieldElementWithInteger {
    /// Interpret `i` as [`FieldElementWithInteger::Integer`] if it's representable in that type and
    /// smaller than the field modulus.
    fn valid_integer_try_from<N>(i: N) -> Result<Self::Integer, FieldError>
    where
        Self::Integer: TryFrom<N>,
    {
        let i_int = Self::Integer::try_from(i).map_err(|_| FieldError::IntegerTryFrom)?;
        if Self::modulus() <= i_int {
            return Err(FieldError::ModulusOverflow);
        }
        Ok(i_int)
    }

    /// Check if the largest number representable with `bits` bits (i.e. 2^bits - 1) is
    /// representable in this field.
    fn valid_integer_bitlength(bits: usize) -> bool {
        if bits >= 8 * Self::ENCODED_SIZE {
            return false;
        }
        if Self::modulus() >> bits != Self::Integer::zero() {
            return true;
        }
        false
    }
}

impl<F: FieldElementWithInteger> FieldElementWithIntegerExt for F {}

/// Methods common to all `FieldElement` implementations that are private to the crate.
pub(crate) trait FieldElementExt: FieldElement {
    /// Try to interpret a slice of [`FieldElement::ENCODED_SIZE`] random bytes as an element in the
    /// field. If the input represents an integer greater than or equal to the field modulus, then
    /// [`ControlFlow::Continue`] is returned instead, to indicate that an enclosing rejection
    /// sampling loop should try again with different random bytes.
    ///
    /// # Panics
    ///
    /// Panics if `bytes` is not of length [`FieldElement::ENCODED_SIZE`].
    fn from_random_rejection(bytes: &[u8]) -> ControlFlow<Self, ()> {
        match Self::try_from_random(bytes) {
            Ok(x) => ControlFlow::Break(x),
            Err(FieldError::ModulusOverflow) => ControlFlow::Continue(()),
            Err(err) => panic!("unexpected error: {err}"),
        }
    }

    /// Generate a uniformly random field element from the provided source of random bytes using
    /// rejection sampling.
    fn generate_random<S: RngCore + ?Sized>(seed_stream: &mut S) -> Self {
        // This is analogous to `Prng::get()`, but does not make use of a persistent buffer of
        // output.
        let mut buffer = [0u8; 64];
        assert!(
            buffer.len() >= Self::ENCODED_SIZE,
            "field is too big for buffer"
        );
        loop {
            seed_stream.fill_bytes(&mut buffer[..Self::ENCODED_SIZE]);
            match Self::from_random_rejection(&buffer[..Self::ENCODED_SIZE]) {
                ControlFlow::Break(x) => return x,
                ControlFlow::Continue(()) => continue,
            }
        }
    }
}

impl<F: FieldElement> FieldElementExt for F {}

/// serde Visitor implementation used to generically deserialize `FieldElement`
/// values from byte arrays.
pub(crate) struct FieldElementVisitor<F: FieldElement> {
    pub(crate) phantom: PhantomData<F>,
}

impl<'de, F: FieldElement> Visitor<'de> for FieldElementVisitor<F> {
    type Value = F;

    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_fmt(format_args!("an array of {} bytes", F::ENCODED_SIZE))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Self::Value::try_from(v).map_err(E::custom)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut bytes = vec![];
        while let Some(byte) = seq.next_element()? {
            bytes.push(byte);
        }

        self.visit_bytes(&bytes)
    }
}

/// Objects with this trait represent an element of `GF(p)`, where `p` is some prime and the
/// field's multiplicative group has a subgroup with an order that is a power of 2, and at least
/// `2^20`.
pub trait NttFriendlyFieldElement: FieldElementWithInteger {
    /// Returns the size of the multiplicative subgroup generated by
    /// [`NttFriendlyFieldElement::generator`].
    fn generator_order() -> Self::Integer;

    /// Returns the generator of the multiplicative subgroup of size
    /// [`NttFriendlyFieldElement::generator_order`].
    fn generator() -> Self;

    /// Returns the `2^l`-th principal root of unity for any `l <= 20`. Note that the `2^0`-th
    /// prinicpal root of unity is `1` by definition.
    fn root(l: usize) -> Option<Self>;
}

macro_rules! make_field {
    (
        $(#[$meta:meta])*
        $elem:ident, $int_internal:ident, $int_conversion:ident, $fp:ident, $encoding_size:literal,
    ) => {
        $(#[$meta])*
        ///
        /// This structure represents a field element in a prime order field. The concrete
        /// representation of the element is via the Montgomery domain. For an element `n` in
        /// `GF(p)`, we store `n * R^-1 mod p` (where `R` is a given power of two). This
        /// representation enables using a more efficient (and branchless) multiplication algorithm,
        /// at the expense of having to convert elements between their Montgomery domain
        /// representation and natural representation. For calculations with many multiplications or
        /// exponentiations, this is worthwhile.
        ///
        /// As an invariant, this integer representing the field element in the Montgomery domain
        /// must be less than the field modulus, `p`.
        #[derive(Clone, Copy, Default)]
        pub struct $elem($int_internal);

        impl $elem {
            /// Attempts to instantiate an `$elem` from the first `Self::ENCODED_SIZE` bytes in the
            /// provided slice. The decoded value will be bitwise-ANDed with `mask` before reducing
            /// it using the field modulus.
            ///
            /// # Errors
            ///
            /// An error is returned if the provided slice is not long enough to encode a field
            /// element or if the decoded value is greater than the field prime.
            ///
            /// # Notes
            ///
            /// We cannot use `u128::from_le_bytes` or `u128::from_be_bytes` because those functions
            /// expect inputs to be exactly 16 bytes long. Our encoding of most field elements is
            /// more compact.
            fn try_from_bytes(bytes: &[u8], mask: $int_internal) -> Result<Self, FieldError> {
                if Self::ENCODED_SIZE > bytes.len() {
                    return Err(FieldError::ShortRead);
                }

                let mut int = 0;
                for i in 0..Self::ENCODED_SIZE {
                    int |= (bytes[i] as $int_internal) << (i << 3);
                }

                int &= mask;

                if int >= $fp::PRIME {
                    return Err(FieldError::ModulusOverflow);
                }
                // FieldParameters::montgomery() will return a value that has been fully reduced
                // mod p, satisfying the invariant on Self.
                Ok(Self($fp::montgomery(int)))
            }
        }

        impl PartialEq for $elem {
            fn eq(&self, rhs: &Self) -> bool {
                // The fields included in this comparison MUST match the fields
                // used in Hash::hash
                // https://doc.rust-lang.org/std/hash/trait.Hash.html#hash-and-eq

                // Check the invariant that the integer representation is fully reduced.
                debug_assert!(self.0 < $fp::PRIME);
                debug_assert!(rhs.0 < $fp::PRIME);

                self.0 == rhs.0
            }
        }

        impl ConstantTimeEq for $elem {
            fn ct_eq(&self, rhs: &Self) -> Choice {
                self.0.ct_eq(&rhs.0)
            }
        }

        impl ConditionallySelectable for $elem {
            fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
                Self($int_internal::conditional_select(&a.0, &b.0, choice))
            }
        }

        impl Hash for $elem {
            fn hash<H: Hasher>(&self, state: &mut H) {
                // The fields included in this hash MUST match the fields used
                // in PartialEq::eq
                // https://doc.rust-lang.org/std/hash/trait.Hash.html#hash-and-eq

                // Check the invariant that the integer representation is fully reduced.
                debug_assert!(self.0 < $fp::PRIME);

                self.0.hash(state);
            }
        }

        impl Eq for $elem {}

        impl Add for $elem {
            type Output = $elem;
            fn add(self, rhs: Self) -> Self {
                // FieldParameters::add() returns a value that has been fully reduced
                // mod p, satisfying the invariant on Self.
                Self($fp::add(self.0, rhs.0))
            }
        }

        impl Add for &$elem {
            type Output = $elem;
            fn add(self, rhs: Self) -> $elem {
                *self + *rhs
            }
        }

        impl AddAssign for $elem {
            fn add_assign(&mut self, rhs: Self) {
                *self = *self + rhs;
            }
        }

        impl Sub for $elem {
            type Output = $elem;
            fn sub(self, rhs: Self) -> Self {
                // We know that self.0 and rhs.0 are both less than p, thus FieldParameters::sub()
                // returns a value less than p, satisfying the invariant on Self.
                Self($fp::sub(self.0, rhs.0))
            }
        }

        impl Sub for &$elem {
            type Output = $elem;
            fn sub(self, rhs: Self) -> $elem {
                *self - *rhs
            }
        }

        impl SubAssign for $elem {
            fn sub_assign(&mut self, rhs: Self) {
                *self = *self - rhs;
            }
        }

        impl Mul for $elem {
            type Output = $elem;
            fn mul(self, rhs: Self) -> Self {
                // FieldParameters::mul() always returns a value less than p, so the invariant on
                // Self is satisfied.
                Self($fp::mul(self.0, rhs.0))
            }
        }

        impl Mul for &$elem {
            type Output = $elem;
            fn mul(self, rhs: Self) -> $elem {
                *self * *rhs
            }
        }

        impl MulAssign for $elem {
            fn mul_assign(&mut self, rhs: Self) {
                *self = *self * rhs;
            }
        }

        impl Div for $elem {
            type Output = $elem;
            #[allow(clippy::suspicious_arithmetic_impl)]
            fn div(self, rhs: Self) -> Self {
                self * rhs.inv()
            }
        }

        impl Div for &$elem {
            type Output = $elem;
            fn div(self, rhs: Self) -> $elem {
                *self / *rhs
            }
        }

        impl DivAssign for $elem {
            fn div_assign(&mut self, rhs: Self) {
                *self = *self / rhs;
            }
        }

        impl Neg for $elem {
            type Output = $elem;
            fn neg(self) -> Self {
                // FieldParameters::neg() will return a value less than p because self.0 is less
                // than p, and neg() dispatches to sub().
                Self($fp::neg(self.0))
            }
        }

        impl Neg for &$elem {
            type Output = $elem;
            fn neg(self) -> $elem {
                -(*self)
            }
        }

        impl From<$int_conversion> for $elem {
            fn from(x: $int_conversion) -> Self {
                // FieldParameters::montgomery() will return a value that has been fully reduced
                // mod p, satisfying the invariant on Self.
                Self($fp::montgomery($int_internal::try_from(x).unwrap()))
            }
        }

        impl From<$elem> for $int_conversion {
            fn from(x: $elem) -> Self {
                $int_conversion::try_from($fp::residue(x.0)).unwrap()
            }
        }

        impl PartialEq<$int_conversion> for $elem {
            fn eq(&self, rhs: &$int_conversion) -> bool {
                $fp::residue(self.0) == $int_internal::try_from(*rhs).unwrap()
            }
        }

        impl<'a> TryFrom<&'a [u8]> for $elem {
            type Error = FieldError;

            fn try_from(bytes: &[u8]) -> Result<Self, FieldError> {
                Self::try_from_bytes(bytes, $int_internal::MAX)
            }
        }

        impl From<$elem> for [u8; $elem::ENCODED_SIZE] {
            fn from(elem: $elem) -> Self {
                let int = $fp::residue(elem.0);
                let mut slice = [0; $elem::ENCODED_SIZE];
                for i in 0..$elem::ENCODED_SIZE {
                    slice[i] = ((int >> (i << 3)) & 0xff) as u8;
                }
                slice
            }
        }

        impl From<$elem> for Vec<u8> {
            fn from(elem: $elem) -> Self {
                <[u8; $elem::ENCODED_SIZE]>::from(elem).to_vec()
            }
        }

        impl Display for $elem {
            fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
                write!(f, "{}", $fp::residue(self.0))
            }
        }

        impl Debug for $elem {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", $fp::residue(self.0))
            }
        }

        // We provide custom [`serde::Serialize`] and [`serde::Deserialize`] implementations because
        // the derived implementations would represent `FieldElement` values as the backing integer,
        // which is not what we want because (1) we can be more efficient in all cases and (2) in
        // some circumstances, [some serializers don't support `u128`](https://github.com/serde-rs/json/issues/625).
        impl Serialize for $elem {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let bytes: [u8; $elem::ENCODED_SIZE] = (*self).into();
                serializer.serialize_bytes(&bytes)
            }
        }

        impl<'de> Deserialize<'de> for $elem {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<$elem, D::Error> {
                deserializer.deserialize_bytes(FieldElementVisitor { phantom: PhantomData })
            }
        }

        impl Encode for $elem {
            fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
                let slice = <[u8; $elem::ENCODED_SIZE]>::from(*self);
                bytes.extend_from_slice(&slice);
                Ok(())
            }

            fn encoded_len(&self) -> Option<usize> {
                Some(Self::ENCODED_SIZE)
            }
        }

        impl Decode for $elem {
            fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
                let mut value = [0u8; $elem::ENCODED_SIZE];
                bytes.read_exact(&mut value)?;
                $elem::try_from_bytes(&value, $int_internal::MAX).map_err(|e| {
                    CodecError::Other(Box::new(e) as Box<dyn std::error::Error + 'static + Send + Sync>)
                })
            }
        }

        impl FieldElement for $elem {
            const ENCODED_SIZE: usize = $encoding_size;
            fn inv(&self) -> Self {
                // FieldParameters::inv() ultimately relies on mul(), and will always return a
                // value less than p.
                Self($fp::inv(self.0))
            }

            fn try_from_random(bytes: &[u8]) -> Result<Self, FieldError> {
                $elem::try_from_bytes(bytes, $fp::BIT_MASK)
            }

            fn zero() -> Self {
                Self(0)
            }

            fn one() -> Self {
                Self($fp::ROOTS[0])
            }
        }

        impl FieldElementWithInteger for $elem {
            type Integer = $int_conversion;

            fn pow(&self, exp: Self::Integer) -> Self {
                // FieldParameters::pow() relies on mul(), and will always return a value less
                // than p.
                Self($fp::pow(self.0, $int_internal::try_from(exp).unwrap()))
            }

            fn modulus() -> Self::Integer {
                $fp::PRIME as $int_conversion
            }
        }

        impl NttFriendlyFieldElement for $elem {
            fn generator() -> Self {
                Self($fp::G)
            }

            fn generator_order() -> Self::Integer {
                1 << (Self::Integer::try_from($fp::NUM_ROOTS).unwrap())
            }

            fn root(l: usize) -> Option<Self> {
                if l < min($fp::ROOTS.len(), $fp::NUM_ROOTS+1) {
                    Some(Self($fp::ROOTS[l]))
                } else {
                    None
                }
            }
        }

        impl Distribution<$elem> for StandardUniform {
            fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> $elem {
                $elem::generate_random(rng)
            }
        }
    };
}

impl Integer for u32 {
    type TryFromUsizeError = <Self as TryFrom<usize>>::Error;
    type TryIntoU64Error = <Self as TryInto<u64>>::Error;

    fn zero() -> Self {
        0
    }

    fn one() -> Self {
        1
    }

    fn checked_ilog2(&self) -> Option<u32> {
        u32::checked_ilog2(*self)
    }
}

impl Integer for u64 {
    type TryFromUsizeError = <Self as TryFrom<usize>>::Error;
    type TryIntoU64Error = <Self as TryInto<u64>>::Error;

    fn zero() -> Self {
        0
    }

    fn one() -> Self {
        1
    }

    fn checked_ilog2(&self) -> Option<u32> {
        u64::checked_ilog2(*self)
    }
}

impl Integer for u128 {
    type TryFromUsizeError = <Self as TryFrom<usize>>::Error;
    type TryIntoU64Error = <Self as TryInto<u64>>::Error;

    fn zero() -> Self {
        0
    }

    fn one() -> Self {
        1
    }

    fn checked_ilog2(&self) -> Option<u32> {
        u128::checked_ilog2(*self)
    }
}

make_field!(
    /// `GF(4293918721)`, a 32-bit field.
    FieldPrio2,
    u32,
    u32,
    FP32,
    4,
);

make_field!(
    /// `GF(18446744069414584321)`, a 64-bit field.
    Field64,
    u64,
    u64,
    FP64,
    8,
);

make_field!(
    /// `GF(340282366920938462946865773367900766209)`, a 128-bit field.
    Field128,
    u128,
    u128,
    FP128,
    16,
);

/// Merge two vectors of fields by summing other_vector into accumulator.
///
/// # Errors
///
/// Fails if the two vectors do not have the same length.
pub(crate) fn merge_vector<F: FieldElement>(
    accumulator: &mut [F],
    other_vector: &[F],
) -> Result<(), FieldError> {
    if accumulator.len() != other_vector.len() {
        return Err(FieldError::InputSizeMismatch);
    }
    add_assign_vector(accumulator, other_vector.iter().copied());

    Ok(())
}

/// Outputs an additive secret sharing of the input.
#[cfg(test)]
pub(crate) fn split_vector<F: FieldElement>(inp: &[F], num_shares: usize) -> Vec<Vec<F>> {
    if num_shares == 0 {
        return vec![];
    }

    let mut outp = Vec::with_capacity(num_shares);
    outp.push(inp.to_vec());

    for _ in 1..num_shares {
        let share = F::random_vector(inp.len());
        sub_assign_vector(&mut outp[0], share.iter().copied());
        outp.push(share);
    }

    outp
}

pub(crate) fn sub_assign_vector<F: FieldElement>(a: &mut [F], b: impl IntoIterator<Item = F>) {
    let mut count = 0;
    for (x, y) in a.iter_mut().zip(b) {
        *x -= y;
        count += 1;
    }
    assert_eq!(a.len(), count);
}

pub(crate) fn add_assign_vector<F: FieldElement>(a: &mut [F], b: impl IntoIterator<Item = F>) {
    let mut count = 0;
    for (x, y) in a.iter_mut().zip(b) {
        *x += y;
        count += 1;
    }
    assert_eq!(a.len(), count);
}

#[cfg(any(test, feature = "multithreaded", feature = "test-util"))]
pub(crate) fn add_vector<F: FieldElement>(mut a: Vec<F>, b: Vec<F>) -> Vec<F> {
    add_assign_vector(&mut a, b.iter().copied());
    a
}

/// `encode_fieldvec` serializes a type that is equivalent to a vector of field elements.
#[inline(always)]
pub(crate) fn encode_fieldvec<F: FieldElement, T: AsRef<[F]>>(
    val: T,
    bytes: &mut Vec<u8>,
) -> Result<(), CodecError> {
    for elem in val.as_ref() {
        elem.encode(bytes)?;
    }
    Ok(())
}

/// `decode_fieldvec` deserializes some number of field elements from a cursor, and advances the
/// cursor's position.
pub(crate) fn decode_fieldvec<F: FieldElement>(
    count: usize,
    input: &mut Cursor<&[u8]>,
) -> Result<Vec<F>, CodecError> {
    let mut vec = Vec::with_capacity(count);
    let mut buffer = [0u8; 64];
    assert!(
        buffer.len() >= F::ENCODED_SIZE,
        "field is too big for buffer"
    );
    for _ in 0..count {
        input.read_exact(&mut buffer[..F::ENCODED_SIZE])?;
        vec.push(
            F::try_from(&buffer[..F::ENCODED_SIZE]).map_err(|e| CodecError::Other(Box::new(e)))?,
        );
    }
    Ok(vec)
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::{FieldElement, FieldElementWithInteger, Integer};
    use crate::{codec::CodecError, field::FieldError, prng::Prng};
    use assert_matches::assert_matches;
    use std::{
        collections::hash_map::DefaultHasher,
        convert::TryFrom,
        hash::{Hash, Hasher},
        io::Cursor,
    };

    /// A test-only copy of `FieldElementWithInteger`.
    ///
    /// This trait is only used in tests, and it is implemented on some fields that do not have
    /// `FieldElementWithInteger` implementations. This separate trait is used in order to avoid
    /// affecting trait resolution with conditional compilation. Additionally, this trait only
    /// requires the `Integer` associated type satisfy `Clone`, not `Copy`, so that it may be used
    /// with arbitrary precision integer implementations.
    pub(crate) trait TestFieldElementWithInteger:
        FieldElement + From<Self::TestInteger>
    {
        type IntegerTryFromError: std::error::Error;
        type TryIntoU64Error: std::error::Error;
        type TestInteger: Integer + From<Self> + Clone;

        fn modulus() -> Self::TestInteger;
    }

    impl<F> TestFieldElementWithInteger for F
    where
        F: FieldElementWithInteger,
    {
        type IntegerTryFromError = <F::Integer as Integer>::TryFromUsizeError;
        type TryIntoU64Error = <F::Integer as Integer>::TryIntoU64Error;
        type TestInteger = F::Integer;

        fn modulus() -> Self::TestInteger {
            <F as FieldElementWithInteger>::modulus()
        }
    }

    pub(crate) fn field_element_test_common<F: TestFieldElementWithInteger>() {
        let mut prng: Prng<F, _> = Prng::new();
        let int_modulus = F::modulus();
        let int_one = F::TestInteger::try_from(1).unwrap();
        let zero = F::zero();
        let one = F::one();
        let two = F::from(F::TestInteger::try_from(2).unwrap());
        let four = F::from(F::TestInteger::try_from(4).unwrap());

        // add
        assert_eq!(F::from(int_modulus.clone() - int_one.clone()) + one, zero);
        assert_eq!(one + one, two);
        assert_eq!(two + F::from(int_modulus.clone()), two);

        // add w/ assignment
        let mut a = prng.get();
        let b = prng.get();
        let c = a + b;
        a += b;
        assert_eq!(a, c);

        // sub
        assert_eq!(zero - one, F::from(int_modulus.clone() - int_one.clone()));
        #[allow(clippy::eq_op)]
        {
            assert_eq!(one - one, zero);
        }
        assert_eq!(one + (-one), zero);
        assert_eq!(two - F::from(int_modulus.clone()), two);
        assert_eq!(one - F::from(int_modulus.clone() - int_one.clone()), two);

        // sub w/ assignment
        let mut a = prng.get();
        let b = prng.get();
        let c = a - b;
        a -= b;
        assert_eq!(a, c);

        // add + sub
        for _ in 0..100 {
            let f = prng.get();
            let g = prng.get();
            assert_eq!(f + g - f - g, zero);
            assert_eq!(f + g - g, f);
            assert_eq!(f + g - f, g);
        }

        // mul
        assert_eq!(two * two, four);
        assert_eq!(two * one, two);
        assert_eq!(two * zero, zero);
        assert_eq!(one * F::from(int_modulus.clone()), zero);

        // mul w/ assignment
        let mut a = prng.get();
        let b = prng.get();
        let c = a * b;
        a *= b;
        assert_eq!(a, c);

        // integer conversion
        assert_eq!(
            F::TestInteger::from(zero),
            F::TestInteger::try_from(0).unwrap()
        );
        assert_eq!(
            F::TestInteger::from(one),
            F::TestInteger::try_from(1).unwrap()
        );
        assert_eq!(
            F::TestInteger::from(two),
            F::TestInteger::try_from(2).unwrap()
        );
        assert_eq!(
            F::TestInteger::from(four),
            F::TestInteger::try_from(4).unwrap()
        );

        // serialization
        let test_inputs = vec![
            zero,
            one,
            prng.get(),
            F::from(int_modulus.clone() - int_one.clone()),
        ];
        for want in test_inputs.iter() {
            let mut bytes = vec![];
            want.encode(&mut bytes).unwrap();

            assert_eq!(bytes.len(), F::ENCODED_SIZE);
            assert_eq!(want.encoded_len().unwrap(), F::ENCODED_SIZE);

            let got = F::get_decoded(&bytes).unwrap();
            assert_eq!(got, *want);
        }

        #[allow(deprecated)]
        {
            let serialized_vec = F::slice_into_byte_vec(&test_inputs);
            let deserialized = F::byte_slice_into_vec(&serialized_vec).unwrap();
            assert_eq!(deserialized, test_inputs);
        }

        let test_input = prng.get();
        let json = serde_json::to_string(&test_input).unwrap();
        let deserialized = serde_json::from_str::<F>(&json).unwrap();
        assert_eq!(deserialized, test_input);

        let value = serde_json::from_str::<serde_json::Value>(&json).unwrap();
        let array = value.as_array().unwrap();
        for element in array {
            element.as_u64().unwrap();
        }

        #[allow(deprecated)]
        {
            let err = F::byte_slice_into_vec(&[0]).unwrap_err();
            assert_matches!(err, FieldError::ShortRead);

            let err = F::byte_slice_into_vec(&vec![0xffu8; F::ENCODED_SIZE]).unwrap_err();
            assert_matches!(err, FieldError::Codec(CodecError::Other(err)) => {
                assert_matches!(err.downcast_ref::<FieldError>(), Some(FieldError::ModulusOverflow));
            });
        }

        let insufficient = vec![0u8; F::ENCODED_SIZE - 1];
        let err = F::try_from(insufficient.as_ref()).unwrap_err();
        assert_matches!(err, FieldError::ShortRead);
        let err = F::decode(&mut Cursor::new(&insufficient)).unwrap_err();
        assert_matches!(err, CodecError::Io(_));

        let err = F::decode(&mut Cursor::new(&vec![0xffu8; F::ENCODED_SIZE])).unwrap_err();
        assert_matches!(err, CodecError::Other(err) => {
            assert_matches!(err.downcast_ref::<FieldError>(), Some(FieldError::ModulusOverflow));
        });

        // equality and hash: Generate many elements, confirm they are not equal, and confirm
        // various products that should be equal have the same hash. Three is chosen as a generator
        // here because it happens to generate fairly large subgroups of (Z/pZ)* for all four
        // primes.
        let three = F::from(F::TestInteger::try_from(3).unwrap());
        let mut powers_of_three = Vec::with_capacity(500);
        let mut power = one;
        for _ in 0..500 {
            powers_of_three.push(power);
            power *= three;
        }
        // Check all these elements are mutually not equal.
        for i in 0..powers_of_three.len() {
            let first = &powers_of_three[i];
            for second in &powers_of_three[0..i] {
                assert_ne!(first, second);
            }
        }

        // Construct an element from a number that needs to be reduced, and test comparisons on it,
        // confirming that it is reduced correctly.
        let p = F::from(int_modulus.clone());
        assert_eq!(p, zero);
        let p_plus_one = F::from(int_modulus + int_one);
        assert_eq!(p_plus_one, one);
    }

    pub(super) fn hash_helper<H: Hash>(input: H) -> u64 {
        let mut hasher = DefaultHasher::new();
        input.hash(&mut hasher);
        hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::test_utils::{field_element_test_common, hash_helper};
    use crate::fp::MAX_ROOTS;
    use crate::prng::Prng;
    use assert_matches::assert_matches;

    #[test]
    fn test_accumulate() {
        let mut lhs = vec![FieldPrio2(1); 10];
        let rhs = vec![FieldPrio2(2); 10];

        merge_vector(&mut lhs, &rhs).unwrap();

        lhs.iter().for_each(|f| assert_eq!(*f, FieldPrio2(3)));
        rhs.iter().for_each(|f| assert_eq!(*f, FieldPrio2(2)));

        let wrong_len = vec![FieldPrio2::zero(); 9];
        let result = merge_vector(&mut lhs, &wrong_len);
        assert_matches!(result, Err(FieldError::InputSizeMismatch));
    }

    fn field_element_test<F: NttFriendlyFieldElement + Hash>() {
        field_element_test_common::<F>();

        let mut prng: Prng<F, _> = Prng::new();
        let int_modulus = F::modulus();
        let int_one = F::Integer::try_from(1).unwrap();
        let zero = F::zero();
        let one = F::one();
        let two = F::from(F::Integer::try_from(2).unwrap());
        let four = F::from(F::Integer::try_from(4).unwrap());

        // div
        assert_eq!(four / two, two);
        #[allow(clippy::eq_op)]
        {
            assert_eq!(two / two, one);
        }
        assert_eq!(zero / two, zero);
        assert_eq!(two / zero, zero); // Undefined behavior
        assert_eq!(zero.inv(), zero); // Undefined behavior

        // div w/ assignment
        let mut a = prng.get();
        let b = prng.get();
        let c = a / b;
        a /= b;
        assert_eq!(a, c);
        assert_eq!(hash_helper(a), hash_helper(c));

        // mul + div
        for _ in 0..100 {
            let f = prng.get();
            if f == zero {
                continue;
            }
            assert_eq!(f * f.inv(), one);
            assert_eq!(f.inv() * f, one);
        }

        // pow
        assert_eq!(two.pow(F::Integer::try_from(0).unwrap()), one);
        assert_eq!(two.pow(int_one), two);
        assert_eq!(two.pow(F::Integer::try_from(2).unwrap()), four);
        assert_eq!(two.pow(int_modulus - int_one), one);
        assert_eq!(two.pow(int_modulus), two);

        // roots
        let mut int_order = F::generator_order();
        for l in 0..MAX_ROOTS + 1 {
            assert_eq!(
                F::generator().pow(int_order),
                F::root(l).unwrap(),
                "failure for F::root({l})"
            );
            int_order = int_order >> 1;
        }

        // formatting
        assert_eq!(format!("{zero}"), "0");
        assert_eq!(format!("{one}"), "1");
        assert_eq!(format!("{zero:?}"), "0");
        assert_eq!(format!("{one:?}"), "1");

        let three = F::from(F::Integer::try_from(3).unwrap());
        let mut powers_of_three = Vec::with_capacity(500);
        let mut power = one;
        for _ in 0..500 {
            powers_of_three.push(power);
            power *= three;
        }

        // Check that 3^i is the same whether it's calculated with pow() or repeated
        // multiplication, with both equality and hash equality.
        for (i, power) in powers_of_three.iter().enumerate() {
            let result = three.pow(F::Integer::try_from(i).unwrap());
            assert_eq!(result, *power);
            let hash1 = hash_helper(power);
            let hash2 = hash_helper(result);
            assert_eq!(hash1, hash2);
        }

        // Check that 3^n = (3^i)*(3^(n-i)), via both equality and hash equality.
        let expected_product = powers_of_three[powers_of_three.len() - 1];
        let expected_hash = hash_helper(expected_product);
        for i in 0..powers_of_three.len() {
            let a = powers_of_three[i];
            let b = powers_of_three[powers_of_three.len() - 1 - i];
            let product = a * b;
            assert_eq!(product, expected_product);
            assert_eq!(hash_helper(product), expected_hash);
        }
    }

    #[test]
    fn test_field_prio2() {
        field_element_test::<FieldPrio2>();
    }

    #[test]
    fn test_field64() {
        field_element_test::<Field64>();
    }

    #[test]
    fn test_field128() {
        field_element_test::<Field128>();
    }

    #[test]
    fn test_encode_into_bitvector() {
        let zero = Field128::zero();
        let one = Field128::one();
        let zero_enc = Field128::encode_as_bitvector(0, 4)
            .unwrap()
            .collect::<Vec<_>>();
        let one_enc = Field128::encode_as_bitvector(1, 4)
            .unwrap()
            .collect::<Vec<_>>();
        let fifteen_enc = Field128::encode_as_bitvector(15, 4)
            .unwrap()
            .collect::<Vec<_>>();
        assert_eq!(zero_enc, [zero; 4]);
        assert_eq!(one_enc, [one, zero, zero, zero]);
        assert_eq!(fifteen_enc, [one; 4]);
        Field128::encode_as_bitvector(16, 4).unwrap_err();
        Field128::encode_as_bitvector(0, 129).unwrap_err();
    }
}
