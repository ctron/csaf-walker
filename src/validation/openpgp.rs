use crate::retrieve::RetrievedAdvisory;
use crate::validation::{ValidationContext, ValidationOptions};
use anyhow::bail;
use sequoia_openpgp::{
    cert::prelude::ValidErasedKeyAmalgamation,
    packet::{key::PublicParts, Signature},
    parse::{
        stream::{DetachedVerifierBuilder, MessageLayer, MessageStructure, VerificationHelper},
        Parse,
    },
    policy::{HashAlgoSecurity, Policy, StandardPolicy},
    types::{AEADAlgorithm, SymmetricAlgorithm},
    Cert, KeyHandle, Packet,
};
use std::fmt::Debug;

struct Helper<'a, C> {
    context: &'a ValidationContext<C>,
}

impl<'a, C> VerificationHelper for Helper<'a, C> {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> sequoia_openpgp::Result<Vec<Cert>> {
        Ok(self.context.keys.iter().map(|k| k.cert.clone()).collect())
    }

    fn check(&mut self, structure: MessageStructure) -> sequoia_openpgp::Result<()> {
        let mut good = false;

        for (i, layer) in structure.into_iter().enumerate() {
            log::trace!("Message ({i}): {layer:?}");

            match (i, layer) {
                (0, MessageLayer::SignatureGroup { results }) => match results.into_iter().next() {
                    Some(Ok(_)) => good = true,
                    Some(Err(err)) => {
                        return Err(sequoia_openpgp::Error::from(err).into());
                    }
                    None => {
                        bail!("No signature");
                    }
                },
                _ => {
                    bail!("Unexpected message structure");
                }
            }
        }

        if !good {
            bail!("Signature verification failed")
        }

        Ok(())
    }
}

#[derive(Debug)]
struct WrappingPolicy<'a>(pub StandardPolicy<'a>);

impl<'a> Policy for WrappingPolicy<'a> {
    fn signature(&self, sig: &Signature, sec: HashAlgoSecurity) -> sequoia_openpgp::Result<()> {
        self.0.signature(sig, sec)
    }

    fn key(&self, ka: &ValidErasedKeyAmalgamation<PublicParts>) -> sequoia_openpgp::Result<()> {
        self.0.key(ka)
    }

    fn symmetric_algorithm(&self, algo: SymmetricAlgorithm) -> sequoia_openpgp::Result<()> {
        self.0.symmetric_algorithm(algo)
    }

    fn aead_algorithm(&self, algo: AEADAlgorithm) -> sequoia_openpgp::Result<()> {
        self.0.aead_algorithm(algo)
    }

    fn packet(&self, packet: &Packet) -> sequoia_openpgp::Result<()> {
        self.0.packet(packet).map_err(|err| {
            log::debug!(
                "Failed to validate packet - tag: {tag:?}, version = {version:?}",
                tag = packet.tag(),
                version = packet.version()
            );
            err
        })
    }
}

pub fn validate_signature<C>(
    options: &ValidationOptions,
    context: &ValidationContext<C>,
    signature: &str,
    retrieved: &RetrievedAdvisory,
) -> Result<(), anyhow::Error> {
    // TODO: we could move this into the context and re-use
    let policy = match options.validation_date {
        Some(time) => StandardPolicy::at(time),
        None => StandardPolicy::new(),
    };
    let policy = WrappingPolicy(policy);
    let mut verifier = DetachedVerifierBuilder::from_bytes(&signature)?.with_policy(
        &policy,
        None,
        Helper { context },
    )?;

    verifier.verify_bytes(&retrieved.data)?;

    Ok(())
}
