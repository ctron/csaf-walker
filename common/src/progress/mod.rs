//! Progress reporting

use indicatif::{MultiProgress, ProgressStyle};
use std::borrow::Cow;

#[derive(Clone, Default)]
pub struct Progress {
    progress: Option<MultiProgress>,
}

impl From<MultiProgress> for Progress {
    fn from(progress: MultiProgress) -> Self {
        Self {
            progress: Some(progress),
        }
    }
}

impl From<()> for Progress {
    fn from(_: ()) -> Self {
        Self { progress: None }
    }
}

impl Progress {
    pub fn start(&self, tasks: usize) -> ProgressBar {
        let Some(progress) = &self.progress else {
            return ProgressBar { bar: None };
        };

        let tasks = tasks.try_into().unwrap_or(u64::MAX);
        let bar = indicatif::ProgressBar::new(tasks);
        bar.set_style(
            ProgressStyle::default_bar()
                .template("{msg:<20} {wide_bar} {pos}/{len} ({eta})")
                .expect("template must parse"),
        );

        ProgressBar {
            bar: Some(progress.add(bar)),
        }
    }

    pub fn wrap_iter<T>(
        &self,
        tasks: usize,
        iter: impl Iterator<Item = T>,
    ) -> impl Iterator<Item = T> {
        match &self.progress {
            Some(progress) => {
                let tasks = tasks.try_into().unwrap_or(u64::MAX);
                let bar = indicatif::ProgressBar::new(tasks);
                bar.set_style(
                    ProgressStyle::default_bar()
                        .template("{wide_bar} {pos}/{len} ({eta})")
                        .expect("template must parse"),
                );

                let bar = progress.add(bar);

                let iter = bar.wrap_iter(iter);
                ProgressIter::Some(iter)
            }
            None => ProgressIter::None(iter),
        }
    }
}

enum ProgressIter<I>
where
    I: Iterator,
{
    None(I),
    Some(indicatif::ProgressBarIter<I>),
}

impl<I> Iterator for ProgressIter<I>
where
    I: Iterator,
{
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::None(iter) => iter.next(),
            Self::Some(iter) => iter.next(),
        }
    }
}

pub struct ProgressBar {
    bar: Option<indicatif::ProgressBar>,
}

impl ProgressBar {
    pub fn tick(&self) {
        if let Some(bar) = &self.bar {
            bar.inc(1);
        }
    }

    pub fn set_message(&self, msg: Cow<'static, str>) {
        if let Some(bar) = &self.bar {
            bar.set_message(msg);
        }
    }

    pub fn println(&self, msg: &str) {
        if let Some(bar) = &self.bar {
            bar.println(msg);
        }
    }
}
