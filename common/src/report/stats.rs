use std::cmp::max;
use std::fs::File;
use std::io::ErrorKind;
use std::path::Path;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReportStatistics {
    /// Timestamp of the report
    #[serde(with = "time::serde::rfc3339")]
    pub last_run: time::OffsetDateTime,

    #[serde(default)]
    pub entries: Vec<Record>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl ReportStatistics {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Error> {
        Ok(serde_json::from_reader(File::open(path)?)?)
    }

    pub fn store(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        Ok(serde_json::to_writer(File::create(path)?, self)?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Record {
    /// Timestamp of the report
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: time::OffsetDateTime,

    /// The total number of documents
    pub total: usize,

    /// The number of documents with an error
    pub errors: usize,
    /// The total number of errors
    pub total_errors: usize,
    /// The number of documents with a warning
    pub warnings: usize,
    /// The total number of warnings
    pub total_warnings: usize,
}

pub fn record(path: impl AsRef<Path>, record: Record) -> Result<(), Error> {
    // load stats, create default if not found, fail otherwise

    let mut stats = match ReportStatistics::load(&path) {
        Ok(stats) => stats,
        Err(Error::Io(err)) if err.kind() == ErrorKind::NotFound => ReportStatistics {
            last_run: OffsetDateTime::now_utc(),
            entries: vec![],
        },
        Err(err) => return Err(err),
    };

    // update last_run timestamp

    stats.last_run = max(stats.last_run, record.timestamp);

    // insert record at the correct position

    let pos = stats
        .entries
        .binary_search_by_key(&record.timestamp, |entry| entry.timestamp)
        .unwrap_or_else(|e| e);
    stats.entries.insert(pos, record);

    // store

    stats.store(path)?;

    // done

    Ok(())
}

pub struct Statistics {
    pub total: usize,
    pub errors: usize,
    pub total_errors: usize,
    pub warnings: usize,
    pub total_warnings: usize,
}

/// Update the stats file with a new record, having the timestamp of `now`.
pub fn record_now(stats_file: Option<&Path>, stats: Statistics) -> Result<(), Error> {
    if let Some(statistics) = &stats_file {
        let Statistics {
            total,
            errors,
            total_errors,
            warnings,
            total_warnings,
        } = stats;

        record(
            statistics,
            Record {
                timestamp: OffsetDateTime::now_utc(),
                total,
                errors,
                total_errors,
                warnings,
                total_warnings,
            },
        )?;
    }

    Ok(())
}
