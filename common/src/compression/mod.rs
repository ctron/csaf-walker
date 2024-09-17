//! Helpers for using compression/decompression.

mod detecting;
mod limit;

pub use detecting::*;
pub use limit::*;

use anyhow::anyhow;
use bytes::Bytes;
use std::io::Write;

/// Decompress a stream, or fail if no encoder was configured.
///
/// This function will not consume the data, but return `None`, if no decompression was required.
/// This allows one to hold on to the original, compressed, data if necessary.
pub fn decompress_opt(data: &[u8], name: &str) -> Option<Result<Bytes, anyhow::Error>> {
    let detector = Detector {
        file_name: Some(name),
        ..Default::default()
    };
    let detected = detector.detect(data).map_err(|err| anyhow!("{err}"));

    detected
        .and_then(|detected| detected.decompress_opt(data).map_err(|err| err.into()))
        .transpose()
}

/// Decompress a stream, or fail if no encoder was configured.
pub fn decompress(data: Bytes, name: &str) -> Result<Bytes, anyhow::Error> {
    decompress_opt(&data, name).unwrap_or_else(|| Ok(data))
}

/// Decompress bz2 using `bzip2-rs` (pure Rust version)
#[cfg(all(feature = "bzip2-rs", not(feature = "bzip2")))]
#[deprecated(since = "0.9.3", note = "Use Compression::decompress instead")]
pub fn decompress_bzip2(data: &[u8]) -> Result<Bytes, std::io::Error> {
    decompress_bzip2_with(data, &DecompressionOptions::default())
}

/// Decompress bz2 using `bzip2-rs` (pure Rust version)
#[cfg(all(feature = "bzip2-rs", not(feature = "bzip2")))]
#[deprecated(since = "0.9.3", note = "Use Compression::decompress instead")]
pub fn decompress_bzip2_with(
    data: &[u8],
    opts: &DecompressionOptions,
) -> Result<Bytes, std::io::Error> {
    let decoder = bzip2_rs::DecoderReader::new(data);
    decompress_limit(decoder, opts.limit)
}

/// Decompress bz2 using `bzip2` (based on `libbz2`).
#[cfg(feature = "bzip2")]
#[deprecated(since = "0.9.3", note = "Use Compression::decompress instead")]
pub fn decompress_bzip2(data: &[u8]) -> Result<Bytes, std::io::Error> {
    decompress_bzip2_with(data, &DecompressionOptions::default())
}

/// Decompress bz2 using `bzip2` (based on `libbz2`).
#[cfg(feature = "bzip2")]
fn decompress_bzip2_with(
    data: &[u8],
    opts: &DecompressionOptions,
) -> Result<Bytes, std::io::Error> {
    let decoder = bzip2::read::BzDecoder::new(data);
    decompress_limit(decoder, opts.limit)
}

/// Decompress xz using `liblzma`.
#[cfg(feature = "liblzma")]
#[deprecated(since = "0.9.3", note = "Use Compression::decompress instead")]
pub fn decompress_xz(data: &[u8]) -> Result<Bytes, std::io::Error> {
    decompress_xz_with(data, &Default::default())
}

/// Decompress xz using `liblzma`.
#[cfg(feature = "liblzma")]
fn decompress_xz_with(data: &[u8], opts: &DecompressionOptions) -> Result<Bytes, std::io::Error> {
    let decoder = liblzma::read::XzDecoder::new(data);
    decompress_limit(decoder, opts.limit)
}

/// Decompress with an uncompressed payload limit.
fn decompress_limit(mut reader: impl std::io::Read, limit: usize) -> Result<Bytes, std::io::Error> {
    let mut data = vec![];

    let data = if limit > 0 {
        let mut writer = LimitWriter::new(data, limit);
        std::io::copy(&mut reader, &mut writer)?;
        writer.flush()?;
        writer.close()
    } else {
        reader.read_to_end(&mut data)?;
        data
    };

    Ok(Bytes::from(data))
}
