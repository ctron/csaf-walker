//! Common helpers for implementing sources

use crate::retrieve::RetrievedDocument;
use std::fmt::{Debug, Display};

pub mod file;

pub trait Source {
    type Error: Display + Debug;
    type Retrieved: RetrievedDocument;
}
