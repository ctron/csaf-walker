pub mod check;

use parking_lot::Mutex;
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, Debug)]
pub struct ReportResult<'d> {
    pub errors: &'d BTreeMap<String, Vec<String>>,
    pub total: usize,
}

pub trait ReportSink {
    fn error(&self, msg: String);
}

/// A no-op report sink
impl ReportSink for () {
    fn error(&self, _msg: String) {}
}

impl ReportSink for (String, Arc<Mutex<BTreeMap<String, Vec<String>>>>) {
    fn error(&self, msg: String) {
        self.1.lock().entry(self.0.clone()).or_default().push(msg);
    }
}
