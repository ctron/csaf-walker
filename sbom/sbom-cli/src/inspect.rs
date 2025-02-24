use crate::common::fix_license;
use sbom_walker::{
    Sbom,
    discover::DiscoveredSbom,
    report::{ReportSink, check},
    retrieve::RetrievedSbom,
    source::Source,
    validation::ValidatedSbom,
};
use walker_common::{compression::decompress, validate::ValidationError};

pub fn inspect_validated(report: &dyn ReportSink, sbom: ValidatedSbom) {
    let ValidatedSbom {
        retrieved:
            RetrievedSbom {
                data,
                discovered: DiscoveredSbom { url, .. },
                ..
            },
    } = sbom;

    let data = decompress(data, url.path());

    let data = match data {
        Ok(data) => data,
        Err(err) => {
            report.error(format!("Failed to decode file: {err}"));
            return;
        }
    };

    let mut value = match serde_json::from_slice(&data) {
        Ok(value) => value,
        Err(err) => {
            report.error(format!(
                "Failed to parse file as JSON: {err} (currently only JSON files are supported)"
            ));
            return;
        }
    };

    if Sbom::is_spdx_json(&value).is_ok() {
        let (new, _) = fix_license(report, value);
        value = new;
    }

    let sbom = match Sbom::try_parse_any_json(value) {
        Ok(sbom) => sbom,
        Err(err) => {
            report.error(format!("Failed to parse file: {err}"));
            return;
        }
    };

    check::all(report, &sbom);
}

pub fn inspect<S: Source>(
    report: &dyn ReportSink,
    sbom: Result<ValidatedSbom, ValidationError<S>>,
) {
    let sbom = match sbom {
        Ok(sbom) => sbom,
        Err(err) => {
            report.error(format!("Failed to retrieve: {err}"));
            return;
        }
    };

    inspect_validated(report, sbom)
}
