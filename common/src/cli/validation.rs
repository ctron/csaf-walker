use crate::validate::ValidationOptions;
use flexible_time::timestamp::StartTimestamp;
use std::time::SystemTime;
use time::{Date, Month, UtcOffset};

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Validation")]
pub struct ValidationArguments {
    /// OpenPGP policy date.
    #[arg(long)]
    policy_date: Option<StartTimestamp>,

    /// Enable OpenPGP v3 signatures. Conflicts with 'policy_date'.
    #[arg(short = '3', long = "v3-signatures", conflicts_with = "policy_date")]
    v3_signatures: bool,
}

impl From<ValidationArguments> for ValidationOptions {
    fn from(value: ValidationArguments) -> Self {
        let validation_date: Option<SystemTime> = match (value.policy_date, value.v3_signatures) {
            (_, true) => Some(SystemTime::from(
                Date::from_calendar_date(2007, Month::January, 1)
                    .expect("policy date is known to parse")
                    .midnight()
                    .assume_offset(UtcOffset::UTC),
            )),
            (Some(date), _) => Some(date.into()),
            _ => None,
        };

        log::debug!("Policy date: {validation_date:?}");

        Self { validation_date }
    }
}
