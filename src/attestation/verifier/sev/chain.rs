// SPDX-License-Identifier: Apache-2.0

use crate::attestation::endorser::sev::{ca, cert, Chain};
use crate::attestation::verifier::Verifiable;
use crate::types::shared::Generation;

use std::convert::TryFrom;
use std::io::Result;

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

/// Infers the platform generation by matching the chain's CEK against each
/// built-in ASK. Lives here rather than alongside [`cert::Chain`] because it
/// depends on [`Verifiable`].
impl TryFrom<&cert::Chain> for Generation {
    type Error = ();

    fn try_from(schain: &cert::Chain) -> std::result::Result<Self, Self::Error> {
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
            return Err(());
        })
    }
}
