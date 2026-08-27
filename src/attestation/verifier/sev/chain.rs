// SPDX-License-Identifier: Apache-2.0

use crate::attestation::endorser::sev::{ca, cert, Chain};
use crate::attestation::verifier::Verifiable;
use crate::types::shared::Generation;

use std::io::{Error, ErrorKind, Result};

impl<'a> Verifiable for &'a ca::Chain {
    type Output = &'a ca::Certificate;

    fn verify(self) -> Result<Self::Output> {
        (&self.ark, &self.ark).verify()?;
        (&self.ark, &self.ask).verify()?;
        Ok(&self.ask)
    }
}

impl<'a> Verifiable for &'a cert::Chain {
    type Output = &'a cert::Certificate;

    fn verify(self) -> Result<Self::Output> {
        (&self.oca, &self.oca).verify()?;
        (&self.oca, &self.pek).verify()?;
        (&self.cek, &self.pek).verify()?;
        (&self.pek, &self.pdh).verify()?;
        Ok(&self.pdh)
    }
}

impl<'a> Verifiable for &'a Chain {
    type Output = &'a cert::Certificate;

    fn verify(self) -> Result<Self::Output> {
        let ask = self.ca.verify()?;
        (ask, &self.sev.cek).verify()?;
        self.sev.verify()
    }
}

/// Infers the platform generation by verifying the chain's CEK against each
/// built-in ASK, returning the generation whose ASK signed it.
///
/// This is a free function rather than a `TryFrom<&cert::Chain> for Generation`
/// impl: inferring the generation requires [`Verifiable`], which only exists
/// under the `verifier` feature. As an impl it would silently vanish for
/// `endorser`-only builds, failing at the call site with an unsatisfied trait
/// bound on [`Generation`]. As a function, the same build fails with an
/// unresolved path that names the module — and therefore the feature — to
/// enable.
///
/// # Errors
///
/// Returns [`ErrorKind::InvalidData`] if no built-in ASK verifies the CEK,
/// which means the chain is not from a recognized AMD platform generation.
pub fn infer_generation(schain: &cert::Chain) -> Result<Generation> {
    let naples: ca::Chain = Generation::Naples.into();
    let rome: ca::Chain = Generation::Rome.into();
    let milan: ca::Chain = Generation::Milan.into();
    let genoa: ca::Chain = Generation::Genoa.into();
    let turin: ca::Chain = Generation::Turin.into();

    Ok(if (&naples.ask, &schain.cek).verify().is_ok() {
        Generation::Naples
    } else if (&rome.ask, &schain.cek).verify().is_ok() {
        Generation::Rome
    } else if (&milan.ask, &schain.cek).verify().is_ok() {
        Generation::Milan
    } else if (&genoa.ask, &schain.cek).verify().is_ok() {
        Generation::Genoa
    } else if (&turin.ask, &schain.cek).verify().is_ok() {
        Generation::Turin
    } else {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "chain CEK was not signed by any known AMD generation ASK",
        ));
    })
}
