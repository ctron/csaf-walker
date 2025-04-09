use bytes::Bytes;
use walker_common::compression::{Compression, DecompressionOptions};

/// Test the case of having an unreasonably large decompressed size.
///
/// The idea is to have a compressed file which, by itself, has an acceptable size. However, which
/// decompresses into an unreasonable large payload. This should be prevented by applying a limit
/// to the decompression.
#[test]
#[cfg(any(feature = "bzip2", feature = "bzip2-rs"))]
fn bz2ip_bomb() {
    let data = include_bytes!("data/bomb.bz2");
    let result = Compression::Bzip2.decompress_with(
        Bytes::from_static(data),
        &DecompressionOptions::new().limit(1024 * 1024),
    );

    assert!(result.is_err())
}

/// Test the case of having an unreasonably large decompressed size.
///
/// The idea is to have a compressed file which, by itself, has an acceptable size. However, which
/// decompresses into an unreasonable large payload. This should be prevented by applying a limit
/// to the decompression.
#[test]
#[cfg(feature = "flate2")]
fn gzip_bomb() {
    let data = include_bytes!("data/bomb.gz");
    let result = Compression::Gzip.decompress_with(
        Bytes::from_static(data),
        &DecompressionOptions::new().limit(1024 * 1024),
    );

    assert!(result.is_err())
}
