use crate::{
    cmd::{DiscoverArguments, FilterArguments, SkipArguments},
    common::walk_visitor,
};
use colored_json::write_colored_json;
use csaf::Csaf;
use csaf_walker::{
    discover::DiscoverConfig, retrieve::RetrievingVisitor, validation::ValidatedAdvisory,
    validation::ValidationVisitor,
};
use walker_common::{
    cli::{
        CommandDefaults, client::ClientArguments, runner::RunnerArguments,
        validation::ValidationArguments,
    },
    progress::Progress,
    since::Since,
    validate::ValidationOptions,
};

/// Discover, retrieve, validate, and print documents.
#[derive(clap::Args, Debug)]
pub struct Fetch {
    #[command(flatten)]
    client: ClientArguments,

    #[command(flatten)]
    discover: DiscoverArguments,

    #[command(flatten)]
    filter: FilterArguments,

    #[command(flatten)]
    validation: ValidationArguments,

    #[command(flatten)]
    runner: RunnerArguments,

    #[command(flatten)]
    skip: SkipArguments,

    #[arg(short, long, default_value = "json")]
    output: String,
}

impl CommandDefaults for Fetch {
    fn progress(&self) -> bool {
        false
    }
}

fn show(output: &str, doc: ValidatedAdvisory) -> anyhow::Result<()> {
    let csaf: Csaf = serde_json::from_slice(&doc.data)?;

    if output == "json" {
        serde_json::to_writer(std::io::stdout().lock(), &csaf)?;
    } else if output == "json-pretty" {
        write_colored_json(&csaf, &mut std::io::stdout().lock())?;
    }

    Ok(())
}

impl Fetch {
    pub async fn run<P: Progress>(self, progress: P) -> anyhow::Result<()> {
        let options: ValidationOptions = self.validation.into();

        let since = Since::new(
            self.skip.since,
            self.skip.since_file,
            self.skip
                .since_file_offset
                .map(|d| d.into())
                .unwrap_or_default(),
        )?;

        let show = async |doc| {
            show(&self.output, doc?)?;

            Ok::<_, anyhow::Error>(())
        };

        walk_visitor(
            progress,
            self.client,
            DiscoverConfig::from(self.discover).with_since(since.since),
            self.filter,
            self.runner,
            async |source| {
                let validation = ValidationVisitor::new(show).with_options(options);
                Ok(RetrievingVisitor::new(source.clone(), validation))
            },
        )
        .await?;

        since.store()?;

        Ok(())
    }
}
