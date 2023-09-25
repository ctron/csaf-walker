use sbom_walker::model::sbom::JsonPayload;
use sbom_walker::Sbom;

#[test]
fn test_cyclonedx_v13_json() {
    let _ =
        Sbom::try_cyclonedx_json(include_bytes!("data/cyclonedx.v1_3.json")).expect("must parse");
}
