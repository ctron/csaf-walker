use bytes::Bytes;

pub fn decompress<'a>(data: Bytes, name: &str) -> Result<Bytes, anyhow::Error> {
    if name.ends_with(".bz2") {
        #[cfg(all(feature = "bzip2", not(feature = "bzip2-rs")))]
        return Ok(decompress_bzip2(&data)?);
        #[cfg(all(feature = "bzip2-rs", not(feature = "bzip2")))]
        return Ok(decompress_bzip2_rs(&data)?);
        #[cfg(all(not(feature = "bzip2-rs"), not(feature = "bzip2")))]
        anyhow::bail!("No bz2 decoder enabled");
    }

    Ok(data)
}

/// Decompress bz2 using `bzip2-rs` (pure Rust version)
#[cfg(feature = "bzip2-rs")]
pub fn decompress_bzip2_rs(data: &[u8]) -> Result<Bytes, std::io::Error> {
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
