use indicatif::{MultiProgress, ProgressStyle};

impl super::Progress for MultiProgress {
    type Instance = indicatif::ProgressBar;

    fn start(&self, work: usize) -> Self::Instance {
        let work = work.try_into().unwrap_or(u64::MAX);
        let bar = indicatif::ProgressBar::new(work);
        bar.set_style(
            ProgressStyle::default_bar()
                .template("{msg:<20} {wide_bar} {pos}/{len} ({eta})")
                .expect("template must parse"),
        );

        self.add(bar)
    }

    fn println(&self, message: &str) {
        let _ = MultiProgress::println(self, message);
    }
}

impl super::ProgressBar for indicatif::ProgressBar {
    async fn increment(&mut self, work: usize) {
        indicatif::ProgressBar::inc(self, work as u64)
    }

    async fn finish(self) {
        indicatif::ProgressBar::finish_and_clear(&self)
    }

    async fn set_message(&mut self, msg: String) {
        indicatif::ProgressBar::set_message(self, msg)
    }
}
