// Copyright (c) 2020 Apple Inc.
// SPDX-License-Identifier: MPL-2.0

#![warn(missing_docs)]

//! Libprio-rs
//!
//! Implementation of Prio: https://crypto.stanford.edu/prio/
//!
//! For now we only support 0 / 1 vectors.

pub mod benchmarked;
pub mod client;
pub mod encrypt;
mod fft;
pub mod field;
mod fp;
pub mod pcp; // TODO(cjpatton) Maybe don't make this public.
mod polynomial;
mod prng;
pub mod server;
pub mod util;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
