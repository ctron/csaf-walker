pub mod indicatif;

use std::borrow::Cow;
use std::ops::Deref;
use std::rc::Rc;
use std::sync::Arc;

#[derive(Clone)]
pub struct Progress(pub Arc<dyn ProgressImpl>);

impl Progress {
    pub fn new<P: ProgressImpl + 'static>(value: P) -> Self {
        Self(Arc::new(value))
    }
}

impl<P: ProgressImpl + 'static> From<P> for Progress {
    fn from(value: P) -> Self {
        Self::new(value)
    }
}

impl Default for Progress {
    fn default() -> Self {
        Self(Arc::new(NoProgress))
    }
}

impl Deref for Progress {
    type Target = dyn ProgressImpl;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

pub trait ProgressImpl {
    fn start(&self, tasks: usize) -> Rc<dyn ProgressBar>;
}

pub trait ProgressBar {
    fn tick(&self);
    fn set_message(&self, msg: Cow<'static, str>);
    fn println(&self, msg: &str);
}

/// A no-op implementation
pub struct NoProgress;

impl ProgressImpl for NoProgress {
    fn start(&self, _tasks: usize) -> Rc<dyn ProgressBar> {
        Rc::new(())
    }
}

impl ProgressBar for () {
    fn tick(&self) {}
    fn set_message(&self, _msg: Cow<'static, str>) {}
    fn println(&self, msg: &str) {
        println!("{}", msg);
    }
}
