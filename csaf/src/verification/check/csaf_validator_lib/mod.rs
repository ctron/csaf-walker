use deno_core::{
    include_js_files, ExtensionBuilder, ExtensionFileSource, JsRuntime, RuntimeOptions,
};

fn create_runtime() -> JsRuntime {
    let csaf_validator_lib = ExtensionBuilder::default()
        .js(include_js_files!(csaf_validator_lib dir "src/verification/check/csaf_validator_lib/js", "bundle.js",).into())
        .build();

    let runtime = JsRuntime::new(RuntimeOptions {
        // extensions: vec![csaf_validator_lib],
        ..Default::default()
    });

    runtime
}

pub fn validate() -> anyhow::Result<()> {
    let mut runtime = create_runtime();

    let result = runtime.execute_script_static("bundle.js", include_str!("js/bundle.js"))?;

    println!("Loaded lib: {result:?}");

    let result = runtime.execute_script_static(
        "validator",
        r#"
//import validate from 'csaf_validator_lib';

await csaf_validator_lib.validate(doc);
"#,
    )?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use tokio::runtime::Handle;

    #[tokio::test]
    async fn test() {
        let result = Handle::current().spawn_blocking(|| validate()).await;

        result.unwrap().unwrap();
    }
}
