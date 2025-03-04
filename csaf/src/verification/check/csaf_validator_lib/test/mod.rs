use super::*;
use csaf::document::*;
use log::LevelFilter;
use std::borrow::Cow;
use std::io::BufReader;
use std::path::Path;
use walker_common::compression::Compression;

fn load_file(path: impl AsRef<Path>) -> Csaf {
    serde_json::from_reader(BufReader::new(
        std::fs::File::open(path).expect("must be able to open file"),
    ))
    .expect("must parse")
}

fn valid_doc() -> Csaf {
    load_file("tests/good.json")
}

fn invalid_doc() -> Csaf {
    Csaf {
        document: Document {
            category: Category::Base,
            publisher: Publisher {
                category: PublisherCategory::Coordinator,
                name: "".to_string(),
                namespace: Url::parse("http://example.com").expect("test URL must parse"),
                contact_details: None,
                issuing_authority: None,
            },
            title: "".to_string(),
            tracking: Tracking {
                current_release_date: Default::default(),
                id: "".to_string(),
                initial_release_date: Default::default(),
                revision_history: vec![],
                status: Status::Draft,
                version: "".to_string(),
                aliases: None,
                generator: None,
            },
            csaf_version: CsafVersion::TwoDotZero,
            acknowledgments: None,
            aggregate_severity: None,
            distribution: None,
            lang: None,
            notes: None,
            references: None,
            source_lang: None,
        },
        product_tree: None,
        vulnerabilities: None,
    }
}

#[tokio::test]
async fn basic_test() {
    let _ = env_logger::builder()
        .filter_level(LevelFilter::Info)
        .try_init();

    let check = CsafValidatorLib::new(Profile::Optional);

    let result = check.check(&invalid_doc()).await;

    log::info!("Result: {result:#?}");

    let result = result.expect("must succeed");

    assert!(!result.is_empty());
}

/// run twice to ensure we can re-use the runtime
#[tokio::test]
async fn test_twice() {
    let _ = env_logger::builder()
        .filter_level(LevelFilter::Info)
        .try_init();

    let check = CsafValidatorLib::new(Profile::Optional);

    let result = check.check(&invalid_doc()).await;
    log::info!("Result: {result:#?}");
    let result = result.expect("must succeed");
    assert!(!result.is_empty());

    let result = check.check(&invalid_doc()).await;

    log::info!("Result: {result:#?}");
    let result = result.expect("must succeed");
    assert!(!result.is_empty());
}

#[tokio::test]
async fn test_ok() {
    let _ = env_logger::builder()
        .filter_level(LevelFilter::Info)
        .try_init();

    let check = CsafValidatorLib::new(Profile::Optional);

    let result = check.check(&valid_doc()).await;
    log::info!("Result: {result:#?}");
    let result = result.expect("must succeed");
    assert_eq!(result, Vec::<CheckError>::new());
}

#[tokio::test]
async fn test_timeout() {
    let _ = env_logger::builder().try_init();

    log::info!("Loading file");

    let data = tokio::fs::read("tests/data/rhsa-2018_3140.json.xz")
        .await
        .expect("test file should open");
    let doc = serde_json::from_slice(
        &Compression::Xz
            .decompress(data.into())
            .expect("must decompress"),
    )
    .expect("test file should parse");

    log::info!("Creating instance");

    let check = CsafValidatorLib::new(Profile::Optional).with_timeout(Duration::from_secs(10));

    log::info!("Running check");

    let result = check.check(&doc).await;
    log::info!("Result: {result:#?}");
    let result = result.expect("must succeed");
    assert_eq!(result, vec![Cow::Borrowed("check timed out")]);
}

#[tokio::test]
async fn performance() {
    let _ = env_logger::builder().try_init();

    log::info!("Loading file");

    log::info!("{:?}", std::env::current_dir());
    let data = tokio::fs::read("csaf/tests/data/rhsa-2018_3140.json.xz")
        .await
        .expect("test file should open");
    let doc = serde_json::from_slice(
        &Compression::Xz
            .decompress(data.into())
            .expect("must decompress"),
    )
    .expect("test file should parse");

    log::info!("Creating instance");

    let check = CsafValidatorLib::new(Profile::Optional);

    log::info!("Running check");

    let result = check.check(&doc).await;
    log::info!("Result: {result:#?}");
    let result = result.expect("must succeed");
    assert_eq!(result, vec![Cow::Borrowed("check timed out")]);
}

#[tokio::test]
// #[ignore = "Requires 'rhsa-2018_3140.json' in the data/ folder"]
async fn test_timeout_next() {
    let _ = env_logger::builder().try_init();

    log::info!("Loading file");

    let doc = serde_json::from_reader(BufReader::new(
        std::fs::File::open("../data/rhsa-2018_3140.json").expect("test file should open"),
    ))
    .expect("test file should parse");

    log::info!("Creating instance");

    let check = CsafValidatorLib::new(Profile::Optional).with_timeout(Duration::from_secs(10));

    log::info!("Running check");

    let result = check.check(&doc).await;
    log::info!("Result: {result:#?}");
    let result = result.expect("must succeed");
    assert_eq!(result, vec![Cow::Borrowed("check timed out")]);

    let result = check.check(&valid_doc()).await;
    log::info!("Result: {result:#?}");
    let result = result.expect("must succeed");
    assert!(result.is_empty());
}

#[tokio::test]
async fn test_ignore() {
    let _ = env_logger::builder()
        .filter_level(LevelFilter::Info)
        .try_init();

    let check = CsafValidatorLib::new(Profile::Optional).ignore(["csaf_2_0", "csaf_2_0_strict"]);

    let result = check.check(&load_file("tests/test_ignore.json")).await;
    log::info!("Result: {result:#?}");
    let result = result.expect("must succeed");
    assert_eq!(result, Vec::<CheckError>::new());
}
