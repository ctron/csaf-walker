//! A validator based on the `csaf_validator_lib`

mod deno;

use crate::verification::check::{Check, CheckError};
use anyhow::anyhow;
use async_trait::async_trait;
use csaf::Csaf;
use deno_core::{
    _ops::RustToV8NoScope, op2, serde_v8, v8, Extension, JsRuntime, ModuleCodeString, Op,
    PollEventLoopOptions, RuntimeOptions, StaticModuleLoader,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt::Debug;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar};
use std::time::Duration;
use tokio::sync::Mutex;
use url::Url;

const MODULE_ID: &str = "internal://bundle.js";

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

impl InnerCheck {
    pub async fn new() -> anyhow::Result<Self> {
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
        &mut self,
        doc: S,
        validations: &[ValidationSet],
        ignore: &HashSet<String>,
        timeout: Option<Duration>,
    ) -> anyhow::Result<Option<D>>
    where
        S: Serialize + Send,
        D: for<'de> Deserialize<'de> + Send + Default + Debug,
    {
        log::debug!("Create arguments");

        let args = {
            let scope = &mut self.runtime.handle_scope();

            let doc = {
                let doc = serde_v8::to_v8(scope, doc)?;
                v8::Global::new(scope, doc)
            };

            let validations = {
                let validations = serde_v8::to_v8(scope, validations)?;
                v8::Global::new(scope, validations)
            };

            let ignore = {
                let set = v8::Set::new(scope);
                for ignore in ignore {
                    let value = serde_v8::to_v8(scope, ignore)?;
                    set.add(scope, value);
                }

                // let ignore = serde_v8::to_v8(scope, ignore)?;
                v8::Global::new(scope, set.to_v8())
            };

            [validations, doc, ignore]
        };

        let cancelled = Arc::new(AtomicBool::new(false));

        let deadline = timeout.map(|duration| {
            log::debug!("Starting deadline");
            let isolate = self.runtime.v8_isolate().thread_safe_handle();

            let lock = Arc::new((std::sync::Mutex::new(()), Condvar::new()));
            let cancelled = cancelled.clone();
            {
                let lock = lock.clone();
                std::thread::spawn(move || {
                    let (lock, notify) = &*lock;
                    let lock = lock.lock().expect("unable to acquire deadline lock");
                    log::debug!("Deadline active");
                    let (_lock, result) = notify
                        .wait_timeout(lock, duration)
                        .expect("unable to await deadline");

                    if result.timed_out() {
                        log::info!("Terminating execution after: {duration:?}");
                        cancelled.store(true, Ordering::Release);
                        isolate.terminate_execution();
                    } else {
                        log::debug!("Deadline cancelled");
                    }
                });
            }

            Deadline(lock)
        });

        log::debug!("Call function");

        let call = self.runtime.call_with_args(&self.runner, &args);

        if cancelled.load(Ordering::Acquire) {
            // already cancelled
            return Ok(None);
        }

        log::debug!("Wait for completion");

        let result = self
            .runtime
            .with_event_loop_promise(call, PollEventLoopOptions::default())
            .await;

        if cancelled.load(Ordering::Acquire) {
            // already cancelled
            return Ok(None);
        }

        drop(deadline);

        // now process the result

        let result = match result {
            Err(err) if err.to_string().ends_with(": execution terminated") => return Ok(None),
            Err(err) => return Err(err),
            Ok(result) => result,
        };

        log::debug!("Extract result");

        let result = {
            let scope = &mut self.runtime.handle_scope();
            let result = v8::Local::new(scope, result);
            let result: D = serde_v8::from_v8(scope, result)?;

            result
        };

        log::trace!("Result: {result:#?}");

        Ok(Some(result))
    }
}

struct Deadline(Arc<(std::sync::Mutex<()>, Condvar)>);

impl Drop for Deadline {
    fn drop(&mut self) {
        log::debug!("Aborting deadline");
        let (_lock, notify) = &*self.0;
        notify.notify_one();
    }
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
    runtime: Arc<Mutex<Vec<InnerCheck>>>,
    validations: Vec<ValidationSet>,
    timeout: Option<Duration>,
    ignore: HashSet<String>,
}

impl CsafValidatorLib {
    pub fn new(profile: Profile) -> Self {
        let runtime = Arc::new(Mutex::new(vec![]));

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
            ignore: Default::default(),
            timeout: None,
        }
    }

    pub fn timeout(mut self, timeout: impl Into<Option<Duration>>) -> Self {
        self.timeout = timeout.into();
        self
    }

    pub fn with_timeout(mut self, timeout: impl Into<Duration>) -> Self {
        self.timeout = Some(timeout.into());
        self
    }

    pub fn without_timeout(mut self) -> Self {
        self.timeout = None;
        self
    }

    pub fn ignore(mut self, ignore: impl IntoIterator<Item = impl ToString>) -> Self {
        self.ignore.clear();
        self.extend_ignore(ignore)
    }

    pub fn add_ignore(mut self, ignore: impl ToString) -> Self {
        self.ignore.insert(ignore.to_string());
        self
    }

    pub fn extend_ignore(mut self, ignore: impl IntoIterator<Item = impl ToString>) -> Self {
        self.ignore
            .extend(ignore.into_iter().map(|s| s.to_string()));
        self
    }
}

#[async_trait(? Send)]
impl Check for CsafValidatorLib {
    async fn check(&self, csaf: &Csaf) -> anyhow::Result<Vec<CheckError>> {
        let mut inner = {
            let mut inner_lock = self.runtime.lock().await;
            match inner_lock.pop() {
                Some(inner) => inner,
                None => InnerCheck::new().await?,
            }
        };

        let test_result = inner
            .validate::<_, TestResult>(csaf, &self.validations, &self.ignore, self.timeout)
            .await?;

        log::trace!("Result: {test_result:?}");

        let Some(test_result) = test_result else {
            return Ok(vec!["check timed out".into()]);
        };

        // not timed out, not failed, we can re-use it
        self.runtime.lock().await.push(inner);

        let mut result = vec![];

        for entry in test_result.tests {
            // we currently only report "failed" tests
            if entry.is_valid {
                continue;
            }

            for error in entry.errors {
                result.push(
                    format!(
                        "{name} ({instance_path}): {message}",
                        name = entry.name,
                        instance_path = error.instance_path,
                        message = error.message
                    )
                    .into(),
                );
            }
        }

        Ok(result)
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

    pub errors: Vec<TestResultEntry>,
    pub warnings: Vec<TestResultEntry>,
    pub infos: Vec<TestResultEntry>,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestResultEntry {
    pub message: String,
    pub instance_path: String,
}

#[cfg(test)]
mod test {
    use super::*;
    use csaf::document::*;
    use log::LevelFilter;
    use std::borrow::Cow;
    use std::io::BufReader;
    use std::path::Path;

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
    #[ignore = "Requires 'rhsa-2018_3140.json' in the data/ folder"]
    async fn test_timeout() {
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

        let check =
            CsafValidatorLib::new(Profile::Optional).ignore(["csaf_2_0", "csaf_2_0_strict"]);

        let result = check.check(&load_file("tests/test_ignore.json")).await;
        log::info!("Result: {result:#?}");
        let result = result.expect("must succeed");
        assert_eq!(result, Vec::<CheckError>::new());
    }
}
