use bytes::Bytes;
use std::collections::HashSet;

#[derive(Debug, thiserror::Error)]
pub enum Error<'a> {
    #[error("unsupported compression: {0}")]
    Unsupported(&'a str),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Compression {
    None,
    #[cfg(any(feature = "bzip2", feature = "bzip2-rs"))]
    Bzip2,
    #[cfg(feature = "liblzma")]
    Xz,
}

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct DecompressionOptions {
    /// The maximum decompressed payload size.
    ///
    /// If the size of the uncompressed payload exceeds this limit, and error would be returned
    /// instead. Zero means, unlimited.
    pub limit: usize,
}

impl DecompressionOptions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the limit of the maximum uncompressed payload size.
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }
}

impl Compression {
    /// Perform decompression.
    ///
    /// Returns the original data for [`Compression::None`].
    pub fn decompress(&self, data: Bytes) -> Result<Bytes, std::io::Error> {
        Ok(self.decompress_opt(&data)?.unwrap_or(data))
    }

    /// Perform decompression.
    ///
    /// Returns the original data for [`Compression::None`].
    pub fn decompress_with(
        &self,
        data: Bytes,
        opts: &DecompressionOptions,
    ) -> Result<Bytes, std::io::Error> {
        Ok(self.decompress_opt_with(&data, opts)?.unwrap_or(data))
    }

    /// Perform decompression.
    ///
    /// Returns `None` for [`Compression::None`]
    pub fn decompress_opt(&self, data: &[u8]) -> Result<Option<Bytes>, std::io::Error> {
        self.decompress_opt_with(data, &Default::default())
    }

    /// Perform decompression.
    ///
    /// Returns `None` for [`Compression::None`]
    pub fn decompress_opt_with(
        &self,
        #[allow(unused_variables)] data: &[u8],
        #[allow(unused_variables)] opts: &DecompressionOptions,
    ) -> Result<Option<Bytes>, std::io::Error> {
        match self {
            #[cfg(any(feature = "bzip2", feature = "bzip2-rs"))]
            Compression::Bzip2 =>
            {
                #[allow(deprecated)]
                super::decompress_bzip2_with(data, opts).map(Some)
            }
            #[cfg(feature = "liblzma")]
            Compression::Xz =>
            {
                #[allow(deprecated)]
                super::decompress_xz_with(data, opts).map(Some)
            }
            Compression::None => Ok(None),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Detector<'a> {
    /// File name
    pub file_name: Option<&'a str>,

    /// Disable detection by magic bytes
    pub disable_magic: bool,

    /// File name extensions to ignore.
    pub ignore_file_extensions: HashSet<&'a str>,
    /// If a file name is present, but the extension is unknown, report as an error
    pub fail_unknown_file_extension: bool,
}

impl<'a> Detector<'a> {
    /// Detect and decompress in a single step.
    pub fn decompress(&'a self, data: Bytes) -> Result<Bytes, Error<'a>> {
        self.decompress_with(data, &Default::default())
    }

    /// Detect and decompress in a single step.
    pub fn decompress_with(
        &'a self,
        data: Bytes,
        opts: &DecompressionOptions,
    ) -> Result<Bytes, Error<'a>> {
        let compression = self.detect(&data)?;
        Ok(compression.decompress_with(data, opts)?)
    }

    pub fn detect(&'a self, #[allow(unused)] data: &[u8]) -> Result<Compression, Error<'a>> {
        // detect by file name extension

        if let Some(file_name) = self.file_name {
            #[cfg(any(feature = "bzip2", feature = "bzip2-rs"))]
            if file_name.ends_with(".bz2") {
                return Ok(Compression::Bzip2);
            }
            #[cfg(feature = "liblzma")]
            if file_name.ends_with(".xz") {
                return Ok(Compression::Xz);
            }
            if self.fail_unknown_file_extension {
                if let Some((_, ext)) = file_name.rsplit_once('.') {
                    if !self.ignore_file_extensions.contains(ext) {
                        return Err(Error::Unsupported(ext));
                    }
                }
            }
        }

        // magic bytes

        if !self.disable_magic {
            #[cfg(any(feature = "bzip2", feature = "bzip2-rs"))]
            if data.starts_with(b"BZh") {
                return Ok(Compression::Bzip2);
            }
            #[cfg(feature = "liblzma")]
            if data.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) {
                return Ok(Compression::Xz);
            }
        }

        // done

        Ok(Compression::None)
    }
}
