//! A validator based on the `csaf_validator_lib`

mod deno;

use crate::verification::check::{
    csaf_validator_lib::deno::{Extractable, Injectable, Json},
    Check, CheckError,
};
use async_trait::async_trait;
use csaf::Csaf;
use deno_core::{
    JsRuntime, ModuleCodeString, PollEventLoopOptions, RuntimeOptions, StaticModuleLoader,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Debug;
use std::rc::Rc;
use std::sync::Arc;
use tokio::sync::Mutex;
use url::Url;

const MODULE_ID: &'static str = "internal://bundle.js";

fn create_runtime() -> JsRuntime {
    let specifier = Url::parse(MODULE_ID).unwrap();
    let code = include_str!("js/bundle.js");

    let runtime = JsRuntime::new(RuntimeOptions {
        module_loader: Some(Rc::new(StaticModuleLoader::with(
            specifier,
            ModuleCodeString::Static(code),
        ))),
        ..Default::default()
    });

    runtime
}

async fn validate<S, D>(
    runtime: &mut JsRuntime,
    doc: S,
    validations: &[ValidationSet],
) -> anyhow::Result<D>
where
    S: Serialize + Send,
    D: for<'de> Deserialize<'de> + Send + Default + Debug,
{
    doc.inject(runtime, "doc")?;
    validations.inject(runtime, "validations")?;

    let module = Url::parse(MODULE_ID)?;
    let mod_id = runtime.load_main_module(&module, None).await?;
    let result = runtime.mod_evaluate(mod_id);
    runtime
        .run_event_loop(PollEventLoopOptions::default())
        .await?;

    result.await?;

    let result: Json<D> = Json::extract(runtime, "result")?;

    log::trace!("Result: {result:#?}");

    Ok(result.0)
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ValidationSet {
    Schema,
    Mandatory,
    Optional,
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Profile {
    Schema,
    Mandatory,
    Optional,
}

pub struct CsafValidatorLib {
    runtime: Arc<Mutex<JsRuntime>>,
    validations: Vec<ValidationSet>,
}

impl CsafValidatorLib {
    pub fn new(profile: Profile) -> Self {
        let runtime = Arc::new(Mutex::new(create_runtime()));

        let validations = match profile {
            Profile::Schema => vec![ValidationSet::Schema],
            Profile::Mandatory => vec![ValidationSet::Schema, ValidationSet::Mandatory],
            Profile::Optional => vec![
                ValidationSet::Schema,
                ValidationSet::Mandatory,
                ValidationSet::Optional,
            ],
        };

        Self {
            runtime,
            validations,
        }
    }
}

/// Result structure, coming from the test call
#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestResult {
    pub tests: Vec<Entry>,
}

/// Test result entry from the tests
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    pub name: String,
    pub is_valid: bool,

    pub errors: Vec<Error>,
    pub warnings: Vec<Value>,
    pub infos: Vec<Value>,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Error {
    pub message: String,
}

#[async_trait(?Send)]
impl Check for CsafValidatorLib {
    async fn check(&self, csaf: &Csaf) -> Vec<CheckError> {
        let test_result: TestResult =
            validate(&mut *self.runtime.lock().await, csaf, &self.validations)
                .await
                .unwrap();

        log::trace!("Result: {test_result:?}");

        let mut result = vec![];

        for entry in test_result.tests {
            // we currently only report "failed" tests
            if entry.is_valid {
                continue;
            }

            for error in entry.errors {
                result.push(
                    format!(
                        "{name}: {message}",
                        name = entry.name,
                        message = error.message
                    )
                    .into(),
                );
            }
        }

        result
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use csaf::document::*;
    use log::LevelFilter;

    #[tokio::test]
    async fn basic_test() {
        let _ = env_logger::builder()
            .filter_level(LevelFilter::Info)
            .try_init();

        let check = CsafValidatorLib::new(Profile::Optional);

        let result = check
            .check(&Csaf {
                document: Document {
                    category: Category::Base,
                    publisher: Publisher {
                        category: PublisherCategory::Coordinator,
                        name: "".to_string(),
                        namespace: Url::parse("http://example.com").unwrap(),
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
            })
            .await;

        log::info!("Result: {result:#?}");

        assert!(!result.is_empty());
    }
}
