mod deno;

use crate::verification::check::csaf_validator_lib::deno::{Extractable, Injectable, Json};
use crate::verification::check::{Check, CheckError};
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

const MODULE: &'static str = "internal://bundle.js";

fn create_runtime() -> JsRuntime {
    /*
        let csaf_validator_lib = ExtensionBuilder::default()
            .js(include_js_files!(csaf_validator_lib dir "src/verification/check/csaf_validator_lib/js", "bundle.js",).into())
            .build();
    */

    let specifier = Url::parse(MODULE).unwrap();
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

async fn validate<S, D>(runtime: &mut JsRuntime, doc: S) -> anyhow::Result<D>
where
    S: Serialize + Send,
    D: for<'de> Deserialize<'de> + Send + Default + Debug,
{
    doc.inject(runtime, "doc").unwrap();

    let module = Url::parse(MODULE).unwrap();
    let mod_id = runtime.load_main_module(&module, None).await?;
    let result = runtime.mod_evaluate(mod_id);
    runtime
        .run_event_loop(PollEventLoopOptions::default())
        .await?;

    result.await?;

    // log::info!("Finished");

    /*
    {
        let global = runtime.main_context();
        let scope = &mut runtime.handle_scope();
        let global = global.open(scope).global(scope);

        let keys = global
            .get_property_names(scope, GetPropertyNamesArgs::default())
            .unwrap();

        for i in 0..keys.length() {
            let key = keys.get_index(scope, i).unwrap();
            let value = global.get(scope, key).unwrap();

            let key_str = key.to_rust_string_lossy(scope);
            let value_str = value.to_rust_string_lossy(scope);

            log::info!("{key_str}: {value_str}");
        }

        // log::info!("Global: {result:?}");
    }*/

    let result: Json<D> = Json::extract(runtime, "result")?;

    log::info!("Result: {result:#?}");

    Ok(result.0)
}

pub struct CsafValidatorLib {
    runtime: Arc<Mutex<JsRuntime>>,
}

impl CsafValidatorLib {
    pub fn new() -> Self {
        let runtime = Arc::new(Mutex::new(create_runtime()));
        Self { runtime }
    }
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestResult {
    pub tests: Vec<Entry>,
}

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
        let test_result: TestResult = validate(&mut *self.runtime.lock().await, csaf)
            .await
            .unwrap();

        log::info!("Result: {test_result:?}");

        let mut result = vec![];

        for entry in test_result.tests {
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
    use serde_json::json;

    #[tokio::test]
    async fn test() {
        let _ = env_logger::builder()
            .filter_level(LevelFilter::Info)
            .try_init();

        let check = CsafValidatorLib::new();

        // let result = Handle::current().spawn_blocking(|| validate()).await;
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

        // result.unwrap().unwrap();
    }
}
