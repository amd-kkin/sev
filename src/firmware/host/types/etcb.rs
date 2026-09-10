// SPDX-License-Identifier: Apache-2.0

//! Extended SNP Trusted Computing Base (TCB) version.
//!
//! [`ExtendedTcbVersion`] is reported only by Venice parts. It is expected to
//! resemble [`TcbVersion`](super::TcbVersion) but carry a different field set.
//!
//! The field set and byte layout are not defined yet, so the struct is
//! currently empty and occupies no space in the attestation report. Filling in
//! the fields is a follow-up.

use std::fmt::{self, Display};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// ExtendedTcbVersion represents the extended TCB version reported by Venice
/// parts.
///
/// The fields are not defined yet. Until they are, this type carries no data
/// and contributes no bytes to the encoded attestation report.
// TODO: add the fields, then implement `Encoder<Generation>`,
// `Decoder<Generation>` and `ByteParser<Generation>` alongside them, mirroring
// `TcbVersion` in `super::snp`. The `ByteParser::Bytes` length depends on the
// layout, which is why those impls are deferred.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub struct ExtendedTcbVersion {}

impl ExtendedTcbVersion {
    /// Creates a new instance of an ExtendedTcbVersion
    pub fn new() -> Self {
        Self {}
    }
}

impl Display for ExtendedTcbVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"Extended TCB Version:
  (no fields defined)"#
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extended_tcb_version_default() {
        assert_eq!(ExtendedTcbVersion::new(), ExtendedTcbVersion::default());
    }

    #[test]
    fn test_extended_tcb_version_copy() {
        let etcb = ExtendedTcbVersion::default();
        let copy = etcb;
        assert_eq!(etcb, copy);
    }

    #[test]
    fn test_extended_tcb_version_display() {
        let expected = r#"Extended TCB Version:
  (no fields defined)"#;
        assert_eq!(expected, ExtendedTcbVersion::default().to_string());
    }
}
