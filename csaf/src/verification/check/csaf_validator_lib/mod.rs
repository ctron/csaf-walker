//! A validator based on the `csaf_validator_lib`

mod deno;

use crate::verification::check::{Check, CheckError};
use anyhow::anyhow;
use async_trait::async_trait;
use csaf::Csaf;
use deno_core::{
    op2, serde_v8, v8, Extension, JsRuntime, ModuleCodeString, Op, PollEventLoopOptions,
    RuntimeOptions, StaticModuleLoader,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Debug;
use std::rc::Rc;
use std::sync::Arc;
use tokio::sync::Mutex;
use url::Url;

const MODULE_ID: &'static str = "internal://bundle.js";

#[derive(Default)]
pub struct FunctionsState {
    pub runner_func: Option<v8::Global<v8::Function>>,
}

#[op2]
pub fn op_register_func(
    #[state] function_state: &mut FunctionsState,
    #[global] f: v8::Global<v8::Function>,
) {
    function_state.runner_func.replace(f);
}

struct InnerCheck {
    runtime: JsRuntime,
    runner: v8::Global<v8::Function>,
}

async fn create_runtime() -> anyhow::Result<InnerCheck> {
    let specifier = Url::parse(MODULE_ID).expect("internal module ID must parse");
    #[cfg(debug_assertions)]
    let code = include_str!("js/bundle.debug.js");
    #[cfg(not(debug_assertions))]
    let code = include_str!("js/bundle.js");

    let ext = Extension {
        ops: std::borrow::Cow::Borrowed(&[op_register_func::DECL]),
        op_state_fn: Some(Box::new(|state| {
            state.put(FunctionsState::default());
        })),
        ..Default::default()
    };

    let mut runtime = JsRuntime::new(RuntimeOptions {
        module_loader: Some(Rc::new(StaticModuleLoader::with(
            specifier,
            ModuleCodeString::Static(code),
        ))),
        extensions: vec![ext],
        ..Default::default()
    });

    let module = Url::parse(MODULE_ID)?;
    let mod_id = runtime.load_main_module(&module, None).await?;
    let result = runtime.mod_evaluate(mod_id);
    runtime
        .run_event_loop(PollEventLoopOptions::default())
        .await?;

    result.await?;

    let state: FunctionsState = runtime.op_state().borrow_mut().take();
    let runner = state
        .runner_func
        .ok_or_else(|| anyhow!("runner function was not initialized"))?;

    Ok(InnerCheck { runtime, runner })
}

async fn validate<S, D>(
    inner: &mut InnerCheck,
    doc: S,
    validations: &[ValidationSet],
) -> anyhow::Result<D>
where
    S: Serialize + Send,
    D: for<'de> Deserialize<'de> + Send + Default + Debug,
{
    let args = {
        let scope = &mut inner.runtime.handle_scope();

        let doc = {
            let doc = serde_v8::to_v8(scope, doc)?;
            v8::Global::new(scope, doc)
        };

        let validations = {
            let validations = serde_v8::to_v8(scope, validations)?;
            v8::Global::new(scope, validations)
        };

        [validations, doc]
    };

    let call = inner.runtime.call_with_args(&inner.runner, &args);

    let result = inner
        .runtime
        .with_event_loop_promise(call, PollEventLoopOptions::default())
        .await?;

    let result = {
        let scope = &mut inner.runtime.handle_scope();
        let result = v8::Local::new(scope, result);
        let result: D = serde_v8::from_v8(scope, result)?;

        result
    };

    log::trace!("Result: {result:#?}");

    Ok(result)
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ValidationSet {
    Schema,
    Mandatory,
    Optional,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Profile {
    Schema,
    Mandatory,
    Optional,
}

pub struct CsafValidatorLib {
    runtime: Arc<Mutex<InnerCheck>>,
    validations: Vec<ValidationSet>,
}

impl CsafValidatorLib {
    pub async fn new(profile: Profile) -> anyhow::Result<Self> {
        let runtime = Arc::new(Mutex::new(create_runtime().await?));

        let validations = match profile {
            Profile::Schema => vec![ValidationSet::Schema],
            Profile::Mandatory => vec![ValidationSet::Schema, ValidationSet::Mandatory],
            Profile::Optional => vec![
                ValidationSet::Schema,
                ValidationSet::Mandatory,
                ValidationSet::Optional,
            ],
        };

        Ok(Self {
            runtime,
            validations,
        })
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
    async fn check(&self, csaf: &Csaf) -> anyhow::Result<Vec<CheckError>> {
        let test_result: TestResult =
            validate(&mut *self.runtime.lock().await, csaf, &self.validations).await?;

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

        Ok(result)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use csaf::document::*;
    use log::LevelFilter;

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

        let check = CsafValidatorLib::new(Profile::Optional)
            .await
            .expect("create instance");

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

        let check = CsafValidatorLib::new(Profile::Optional)
            .await
            .expect("create instance");

        let result = check.check(&invalid_doc()).await;
        log::info!("Result: {result:#?}");
        let result = result.expect("must succeed");
        assert!(!result.is_empty());

        let result = check.check(&invalid_doc()).await;

        log::info!("Result: {result:#?}");
        let result = result.expect("must succeed");
        assert!(!result.is_empty());
    }
}
