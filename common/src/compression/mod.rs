//! Helpers for using compression/decompression.

mod detecting;
pub use detecting::*;

use anyhow::anyhow;
use bytes::Bytes;

/// Decompress a bz2 stream, or fail if no encoder was configured.
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

/// Decompress a bz2 stream, or fail if no encoder was configured.
pub fn decompress(data: Bytes, name: &str) -> Result<Bytes, anyhow::Error> {
    decompress_opt(&data, name).unwrap_or_else(|| Ok(data))
}

/// Decompress bz2 using `bzip2-rs` (pure Rust version)
#[cfg(all(feature = "bzip2-rs", not(feature = "bzip2")))]
pub fn decompress_bzip2(data: &[u8]) -> Result<Bytes, std::io::Error> {
    use std::io::Read;

    let mut decoder = bzip2_rs::DecoderReader::new(data);
    let mut data = vec![];
    decoder.read_to_end(&mut data)?;
    Ok(Bytes::from(data))
}

/// Decompress bz2 using `bzip2` (based on `libbz2`).
#[cfg(feature = "bzip2")]
pub fn decompress_bzip2(data: &[u8]) -> Result<Bytes, std::io::Error> {
    use std::io::Read;

    let mut decoder = bzip2::read::BzDecoder::new(data);
    let mut data = vec![];
    decoder.read_to_end(&mut data)?;

    Ok(Bytes::from(data))
}

/// Decompress xz using `liblzma`.
#[cfg(feature = "liblzma")]
pub fn decompress_xz(data: &[u8]) -> Result<Bytes, std::io::Error> {
    use std::io::Read;

    let mut decoder = liblzma::read::XzDecoder::new(data);
    let mut data = vec![];
    decoder.read_to_end(&mut data)?;

    Ok(Bytes::from(data))
}
