use bytes::Bytes;

/// Decompress a bz2 stream, or fail if no encoder was configured.
///
/// This function will not consume the data, but return `None`, if no decompression was required.
/// This allows one to hold on to the original, compressed, data if necessary.
pub fn decompress_opt(_data: &[u8], name: &str) -> Option<Result<Bytes, anyhow::Error>> {
    if name.ends_with(".bz2") {
        #[cfg(any(feature = "bzip2", feature = "bzip2-rs"))]
        return Some(decompress_bzip2(&_data).map_err(|err| err.into()));
        #[cfg(not(any(feature = "bzip2", feature = "bzip2-rs")))]
        return Some(Err(anyhow::anyhow!("No bz2 decoder enabled")));
    }

    None
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
