use std::io::{Error, ErrorKind, Write};

/// A writer, limiting the output. Failing if more data is written.
pub struct LimitWriter<W>
where
    W: Write,
{
    writer: W,
    limit: usize,
    current: usize,
}

impl<W> LimitWriter<W>
where
    W: Write,
{
    /// Create a new writer, providing the limit.
    pub fn new(writer: W, limit: usize) -> Self {
        Self {
            writer,
            limit,
            current: 0,
        }
    }

    /// Close writer, return the inner writer.
    ///
    /// Note: Closing the writer will not flush it before.
    pub fn close(self) -> W {
        self.writer
    }
}

impl<W> Write for LimitWriter<W>
where
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // check what is remaining
        let remaining = self.limit.saturating_sub(self.current);
        // if noting is left ...
        if remaining == 0 {
            // ... return an error
            return Err(Error::new(ErrorKind::WriteZero, "write limit exceeded"));
        }

        // write out remaining bytes, maxing out at limit
        let to_write = remaining.min(buf.len());
        let bytes_written = self.writer.write(&buf[..to_write])?;
        self.current += bytes_written;

        Ok(bytes_written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

#[cfg(test)]
mod test {
    use crate::compression::LimitWriter;
    use std::io::{Cursor, Write};

    fn perform_write(data: &[u8], limit: usize) -> Result<Vec<u8>, std::io::Error> {
        let mut out = LimitWriter::new(vec![], limit);
        std::io::copy(&mut Cursor::new(data), &mut out)?;
        out.flush()?;

        Ok(out.close())
    }

    #[test]
    fn write_ok() {
        assert!(matches!(
            perform_write(b"0123456789", 100).as_deref(),
            Ok(b"0123456789")
        ));
        assert!(matches!(perform_write(b"", 100).as_deref(), Ok(b"")));
        assert!(matches!(
            perform_write(b"0123456789", 10).as_deref(),
            Ok(b"0123456789")
        ));
        assert!(matches!(
            perform_write(b"012345678", 10).as_deref(),
            Ok(b"012345678")
        ));
    }

    #[test]
    fn write_err() {
        assert!(perform_write(b"01234567890", 10).is_err(),);
        assert!(perform_write(b"012345678901", 10).is_err(),);
    }
}
