#[cfg(feature = "cyclonedx-bom")]
#[test]
fn test_cyclonedx_v13_json() {
    let _ = sbom_walker::Sbom::try_cyclonedx_json(include_bytes!("data/cyclonedx.v1_3.json"))
        .expect("must parse");
}
