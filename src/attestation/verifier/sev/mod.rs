// SPDX-License-Identifier: Apache-2.0

//! Legacy SEV attestation verification.

mod cert;
mod chain;
mod report;

pub use self::chain::infer_generation;
