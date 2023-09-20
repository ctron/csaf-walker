use super::{ProgressBar, ProgressImpl};
use indicatif::{MultiProgress, ProgressStyle};
use std::borrow::Cow;
use std::rc::Rc;

pub struct Indicatif;

impl ProgressImpl for Indicatif {
    fn start(&self, tasks: usize) -> Rc<dyn ProgressBar> {
        let bar = indicatif::ProgressBar::new(tasks.try_into().unwrap_or(u64::MAX));
        bar.set_style(
            ProgressStyle::default_bar()
                .template("{msg} {wide_bar} {pos}/{len} ({eta})")
                .unwrap(),
        );
        Rc::new(IndicatifProgressBar(bar))
    }
}

pub struct IndicatifProgressBar(indicatif::ProgressBar);

impl ProgressBar for IndicatifProgressBar {
    fn tick(&self) {
        self.0.inc(1)
    }

    fn set_message(&self, msg: Cow<'static, str>) {
        self.0.set_message(msg);
    }
}

pub struct MultiIndicatif(pub MultiProgress);

impl ProgressImpl for MultiIndicatif {
    fn start(&self, tasks: usize) -> Rc<dyn ProgressBar> {
        let bar = indicatif::ProgressBar::new(tasks.try_into().unwrap_or(u64::MAX));
        bar.set_style(
            ProgressStyle::default_bar()
                .template("{msg} {wide_bar} {pos}/{len} ({eta})")
                .unwrap(),
        );
        let bar = self.0.add(bar);
        Rc::new(IndicatifProgressBar(bar))
    }
}
