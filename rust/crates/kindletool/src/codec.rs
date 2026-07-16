use std::io::{self, Read, Write};

include!("tables_generated.rs");

/// Transform bytes with Amazon's update-package obfuscation table.
pub fn mangle(bytes: &mut [u8]) {
    bytes
        .iter_mut()
        .for_each(|byte| *byte = PTOG[*byte as usize]);
}

/// Reverse Amazon's update-package obfuscation.
pub fn demangle(bytes: &mut [u8]) {
    bytes
        .iter_mut()
        .for_each(|byte| *byte = GTOP[*byte as usize]);
}

/// Reader adapter that mangles bytes after reading them from its inner stream.
pub struct MangleReader<R> {
    inner: R,
}

impl<R> MangleReader<R> {
    /// Wrap an input stream.
    pub const fn new(inner: R) -> Self {
        Self { inner }
    }

    /// Return the wrapped stream.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for MangleReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        mangle(&mut buffer[..count]);
        Ok(count)
    }
}

/// Reader adapter that demangles bytes after reading them from its inner stream.
pub struct DemangleReader<R> {
    inner: R,
}

impl<R> DemangleReader<R> {
    /// Wrap an input stream.
    pub const fn new(inner: R) -> Self {
        Self { inner }
    }

    /// Return the wrapped stream.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for DemangleReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        demangle(&mut buffer[..count]);
        Ok(count)
    }
}

/// Writer adapter that mangles every written buffer before forwarding it.
pub struct MangleWriter<W> {
    inner: W,
}

impl<W> MangleWriter<W> {
    /// Wrap an output stream.
    pub const fn new(inner: W) -> Self {
        Self { inner }
    }

    /// Return the wrapped stream.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for MangleWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut encoded = buffer.to_vec();
        mangle(&mut encoded);
        self.inner.write_all(&encoded)?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Writer adapter that demangles every written buffer before forwarding it.
pub struct DemangleWriter<W> {
    inner: W,
}

impl<W> DemangleWriter<W> {
    /// Wrap an output stream.
    pub const fn new(inner: W) -> Self {
        Self { inner }
    }

    /// Return the wrapped stream.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for DemangleWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut decoded = buffer.to_vec();
        demangle(&mut decoded);
        self.inner.write_all(&decoded)?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Copy a stream while applying Amazon's update-package obfuscation.
pub fn copy_mangled<R: Read, W: Write>(mut reader: R, mut writer: W) -> io::Result<u64> {
    io::copy(&mut MangleReader::new(&mut reader), &mut writer)
}

/// Copy a stream while reversing Amazon's update-package obfuscation.
pub fn copy_demangled<R: Read, W: Write>(mut reader: R, mut writer: W) -> io::Result<u64> {
    io::copy(&mut DemangleReader::new(&mut reader), &mut writer)
}

#[cfg(test)]
mod tests {
    use super::{DemangleWriter, MangleWriter, copy_demangled, copy_mangled, demangle, mangle};
    use proptest::prelude::*;
    use std::io::{Cursor, Read, Write};

    struct ChunkedReader<R> {
        inner: R,
        chunk: usize,
    }

    impl<R: Read> Read for ChunkedReader<R> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let length = buffer.len().min(self.chunk);
            self.inner.read(&mut buffer[..length])
        }
    }

    #[test]
    fn all_byte_values_round_trip() {
        let mut data: Vec<u8> = (0..=255).collect();
        let original = data.clone();
        mangle(&mut data);
        demangle(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn every_small_chunk_boundary_round_trips() {
        let input = (0_u8..=255).cycle().take(2049).collect::<Vec<_>>();
        for chunk in 1..=257 {
            let mut encoded = Vec::new();
            copy_mangled(
                &mut ChunkedReader {
                    inner: Cursor::new(&input),
                    chunk,
                },
                &mut encoded,
            )
            .unwrap();
            let mut decoded = Vec::new();
            copy_demangled(
                &mut ChunkedReader {
                    inner: Cursor::new(encoded),
                    chunk,
                },
                &mut decoded,
            )
            .unwrap();
            assert_eq!(decoded, input, "failed at chunk size {chunk}");
        }
    }

    #[test]
    fn writer_adapters_preserve_arbitrary_write_boundaries() {
        let input = (0_u8..=255).cycle().take(1027).collect::<Vec<_>>();
        let mut encoded = MangleWriter::new(Vec::new());
        for chunk in input.chunks(17) {
            encoded.write_all(chunk).unwrap();
        }
        let mut decoded = DemangleWriter::new(Vec::new());
        for chunk in encoded.into_inner().chunks(31) {
            decoded.write_all(chunk).unwrap();
        }
        assert_eq!(decoded.into_inner(), input);
    }

    proptest! {
        #[test]
        fn arbitrary_streams_round_trip(data: Vec<u8>) {
            let mut encoded = Vec::new();
            copy_mangled(Cursor::new(&data), &mut encoded).unwrap();
            let mut decoded = Vec::new();
            copy_demangled(Cursor::new(encoded), &mut decoded).unwrap();
            prop_assert_eq!(decoded, data);
        }
    }
}
