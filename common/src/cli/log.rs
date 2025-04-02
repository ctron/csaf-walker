use env_logger::Builder;
use indicatif::MultiProgress;
use indicatif_log_bridge::LogWrapper;
use log::LevelFilter;
use std::io::Write;

#[derive(Clone, Debug, clap::Args)]
pub struct Logging {
    /// Be quiet. Conflicts with 'verbose'.
    #[arg(short, long, conflicts_with = "verbose", global = true)]
    pub quiet: bool,

    /// Be more verbose. May be repeated multiple times to increase verbosity.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Add timestamps to the output messages
    #[arg(long, global = true)]
    pub log_timestamps: bool,

    /// Disable progress bar
    #[arg(long, global = true, conflicts_with = "progress")]
    pub no_progress: bool,

    /// Enable progress bar
    #[arg(long, global = true)]
    pub progress: bool,

    /// Provide a RUST_LOG filter, conflicts with --verbose and --quiet
    #[arg(long, global = true, conflicts_with_all(["verbose", "quiet"]), env("RUST_LOG"))]
    pub log: Option<String>,
}

impl Logging {
    pub fn init(
        self,
        app_modules: &[&'static str],
        default_progress: bool,
    ) -> Option<MultiProgress> {
        // init logging

        let mut builder = Builder::new();

        match self.log {
            Some(log) => {
                builder.parse_filters(&log);
            }
            None => {
                // remove timestamps

                if !self.log_timestamps {
                    builder.format(|buf, record| writeln!(buf, "{}", record.args()));
                }

                // for app modules
                let app_modules = |builder: &mut Builder, level| {
                    builder.filter_module("walker_common", level);
                    for module in app_modules {
                        builder.filter_module(module, level);
                    }
                };

                // log level

                match (self.quiet, self.verbose) {
                    (true, _) => {
                        builder.filter_level(LevelFilter::Off);
                    }
                    (_, 0) => {
                        builder.filter_level(LevelFilter::Warn);
                    }
                    (_, 1) => {
                        app_modules(builder.filter_level(LevelFilter::Warn), LevelFilter::Info)
                    }
                    (_, 2) => {
                        app_modules(builder.filter_level(LevelFilter::Warn), LevelFilter::Debug)
                    }
                    (_, 3) => {
                        app_modules(builder.filter_level(LevelFilter::Info), LevelFilter::Debug)
                    }
                    (_, 4) => {
                        builder.filter_level(LevelFilter::Debug);
                    }
                    (_, 5) => {
                        app_modules(builder.filter_level(LevelFilter::Debug), LevelFilter::Trace)
                    }
                    (_, _) => {
                        builder.filter_level(LevelFilter::Trace);
                    }
                };
            }
        };

        // init the progress meter

        let no_progress = match (self.no_progress, self.progress) {
            (true, _) => true,
            (_, true) => false,
            _ => !default_progress,
        };

        match self.quiet | no_progress {
            true => {
                builder.init();
                None
            }
            false => {
                let logger = builder.build();
                let max_level = logger.filter();
                let multi = MultiProgress::new();
                let log = LogWrapper::new(multi.clone(), logger);
                // NOTE: LogWrapper::try_init is buggy and messes up the log levels
                let _ = log::set_boxed_logger(Box::new(log));
                log::set_max_level(max_level);

                Some(multi)
            }
        }
    }
}
