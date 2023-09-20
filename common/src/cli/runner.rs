#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Runner")]
pub struct RunnerArguments {
    /// Number of workers, too many parallel requests might make you violate request rates. NOTE: A number of zero will spawn an unlimited amount of workers.
    #[arg(short, long, default_value = "1")]
    pub workers: usize,
}
