use crate::model::metadata;
use sequoia_openpgp::cert::CertParser;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::Cert;
use std::ops::Deref;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Key transport error: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("OpenPGP key error: {0}")]
    OpenPgp(#[from] anyhow::Error),
    #[error("Expected public key, found: {0}")]
    WrongKeyType(String),
    #[error("Fingerprint mismatch - expected: {expected}, actual: {actual}")]
    FingerprintMismatch { actual: String, expected: String },
}

#[derive(Clone, Debug)]
pub struct PublicKey {
    pub cert: Cert,
}

impl Deref for PublicKey {
    type Target = Cert;

    fn deref(&self) -> &Self::Target {
        &self.cert
    }
}

pub async fn fetch_key(
    client: &reqwest::Client,
    key_source: &metadata::Key,
) -> Result<Vec<PublicKey>, Error> {
    let bytes = client
        .get(key_source.url.clone())
        .send()
        .await?
        .bytes()
        .await?;

    let certs = CertParser::from_bytes(&bytes)?.collect::<Result<Vec<_>, _>>()?;

    for cert in &certs {
        if let Some(expected) = &key_source.fingerprint {
            let actual = cert.fingerprint().to_hex();
            if &actual != expected {
                return Err(Error::FingerprintMismatch {
                    actual,
                    expected: expected.to_string(),
                });
            }
        }
    }

    Ok(certs.into_iter().map(|cert| PublicKey { cert }).collect())
}
