use crate::discover::DiscoveredSbom;
use crate::model::sbom::ParseAnyError;
use crate::retrieve::RetrievedSbom;
use crate::validation::{ValidatedSbom, ValidationError};
use crate::Sbom;
use std::collections::BTreeMap;
use tokio::task;
use walker_common::compression::decompress;

pub mod render;

#[derive(Debug, thiserror::Error)]
pub enum SbomError {
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    Parse(#[from] ParseAnyError),
    #[error(transparent)]
    Decompression(anyhow::Error),
}

#[derive(Clone, Debug)]
pub struct ReportResult<'d> {
    pub errors: &'d BTreeMap<String, SbomError>,
    pub total: usize,
}

pub async fn inspect(sbom: Result<ValidatedSbom, ValidationError>) -> Result<(), SbomError> {
    let sbom = sbom?;
    let ValidatedSbom {
        retrieved:
            RetrievedSbom {
                data,
                discovered: DiscoveredSbom { url, .. },
                ..
            },
    } = sbom;

    let data = task::spawn_blocking(move || decompress(data, url.path()))
        .await
        .expect("unable to spawn decompression")
        .map_err(SbomError::Decompression)?;

    let _ = Sbom::try_parse_any(&data)?;

    Ok(())
}
