use deno_core::{serde_v8, v8, JsRuntime};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;

pub trait Injectable: Sized + Send {
    type Error: std::error::Error + Send + Sync;

    fn inject(self, runtime: &mut JsRuntime, name: &str) -> Result<(), Self::Error>;
}

pub trait Extractable: Sized + Send {
    type Error: std::error::Error + Send + Sync;

    fn extract(runtime: &mut JsRuntime, name: &str) -> Result<Self, Self::Error>;
}

pub trait Returnable: Sized + Send {
    type Error: std::error::Error + Send + Sync;

    #[allow(unused)]
    fn r#return(
        runtime: &mut JsRuntime,
        global: v8::Global<v8::Value>,
    ) -> Result<Self, Self::Error>;
}

impl<T> Injectable for T
where
    T: Serialize + Send,
{
    type Error = serde_v8::Error;

    fn inject(self, runtime: &mut JsRuntime, name: &str) -> Result<(), Self::Error> {
        let global = runtime.main_context();
        let scope = &mut runtime.handle_scope();
        let global = global.open(scope).global(scope);

        let key = serde_v8::to_v8(scope, name)?;
        let value = serde_v8::to_v8(scope, self)?;
        global.set(scope, key, value);

        Ok(())
    }
}

impl<T> Injectable for Json<T>
where
    T: Serialize + Send,
{
    type Error = serde_v8::Error;

    fn inject(self, runtime: &mut JsRuntime, name: &str) -> Result<(), Self::Error> {
        self.0.inject(runtime, name)
    }
}

impl Extractable for () {
    type Error = Infallible;

    fn extract(_: &mut JsRuntime, _: &str) -> Result<Self, Self::Error> {
        Ok(())
    }
}

impl<T> Extractable for Option<T>
where
    for<'de> T: Deserialize<'de> + Send,
{
    type Error = serde_v8::Error;

    fn extract(runtime: &mut JsRuntime, name: &str) -> Result<Option<T>, Self::Error> {
        let global = runtime.main_context();
        let scope = &mut runtime.handle_scope();
        let global = global.open(scope).global(scope);

        let key = serde_v8::to_v8(scope, name)?;
        Ok(match global.get(scope, key) {
            Some(value) => Some(serde_v8::from_v8(scope, value)?),
            None => None,
        })
    }
}

impl<T> Extractable for Json<T>
where
    for<'de> T: Deserialize<'de> + Send + Default,
{
    type Error = serde_v8::Error;

    fn extract(runtime: &mut JsRuntime, name: &str) -> Result<Self, Self::Error> {
        Option::<T>::extract(runtime, name).map(|o| Json(o.unwrap_or_default()))
    }
}

#[derive(Debug)]
pub struct Json<T>(pub T);

impl<T> Returnable for T
where
    for<'de> T: Deserialize<'de> + Send,
{
    type Error = serde_v8::Error;

    fn r#return(
        runtime: &mut JsRuntime,
        global: v8::Global<v8::Value>,
    ) -> Result<Self, Self::Error> {
        let scope = &mut runtime.handle_scope();
        let local = v8::Local::new(scope, global);
        serde_v8::from_v8(scope, local)
    }
}
