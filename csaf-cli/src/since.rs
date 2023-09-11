use std::fs::File;
use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct SinceState {
    pub last_run: SystemTime,
}

impl SinceState {
    /// Load the since state
    pub fn load<R>(reader: R) -> anyhow::Result<Self>
    where
        R: Read,
    {
        Ok(serde_json::from_reader(reader)?)
    }

    /// Load the since state from a file, returning [`None`] if the file doesn't exist.
    pub fn load_from<F>(file: F) -> anyhow::Result<Option<Self>>
    where
        F: AsRef<Path>,
    {
        match File::open(file) {
            Ok(file) => Self::load(BufReader::new(file)).map(Option::Some),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    /// Store the since state.
    pub fn store<W>(&self, writer: W) -> anyhow::Result<()>
    where
        W: Write,
    {
        Ok(serde_json::to_writer(writer, &self)?)
    }
}

/// Load and record since state
pub struct Since {
    pub since: Option<SystemTime>,
    pub last_run: SystemTime,
    pub since_file: Option<PathBuf>,
}

impl Deref for Since {
    type Target = Option<SystemTime>;

    fn deref(&self) -> &Self::Target {
        &self.since
    }
}

impl Since {
    pub fn new(
        since: Option<impl Into<SystemTime>>,
        since_file: Option<PathBuf>,
    ) -> anyhow::Result<Self> {
        let last_run = SystemTime::now();
        let since = match (since, &since_file) {
            // try file, then fall back to dedicated "since"
            (skip, Some(file)) => SinceState::load_from(file)?
                .map(|state| state.last_run)
                .or(skip),
            // dedicated "since" value
            (Some(skip), None) => Some(skip.into()),
            // no "since" at all
            (None, None) => None,
        };

        Ok(Since {
            since,
            last_run,
            since_file,
        })
    }

    pub fn store(self) -> anyhow::Result<()> {
        if let Some(path) = &self.since_file {
            SinceState {
                last_run: self.last_run,
            }
            .store(BufWriter::new(File::create(path)?))?;
        }
        Ok(())
    }
}
