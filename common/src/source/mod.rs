//! Common helpers for implementing sources

use crate::utils::url::Urlify;
use std::fmt::{Debug, Display};

pub mod file;

pub trait Source {
    type Error: Display + Debug;
}
