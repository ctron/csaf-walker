use bytes::Bytes;

/// Decompress a bz2 stream, or fail if no encoder was configured.
pub fn decompress<'a>(data: Bytes, name: &str) -> Result<Bytes, anyhow::Error> {
    if name.ends_with(".bz2") {
        #[cfg(any(feature = "bzip2", feature = "bzip2-rs"))]
        return Ok(decompress_bzip2(&data)?);
        #[cfg(not(any(feature = "bzip2", feature = "bzip2-rs")))]
        anyhow::bail!("No bz2 decoder enabled");
    }

    Ok(data)
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
