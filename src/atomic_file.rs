//! Atomic publication with an exclusively owned temporary file.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

pub(crate) fn write(path: &Path, parts: &[&[u8]]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".astdiff-")
        .tempfile_in(parent)
        .with_context(|| format!("cannot create temporary output in {}", parent.display()))?;
    for part in parts {
        temporary.write_all(part)?;
    }
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("cannot publish {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_temporary_files_are_never_owned_or_removed() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("result");
        let occupied = directory
            .path()
            .join(format!(".result.{}.tmp", std::process::id()));
        std::fs::write(&occupied, b"another writer").unwrap();
        write(&output, &[b"header", b"payload"]).unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), b"headerpayload");
        assert_eq!(std::fs::read(&occupied).unwrap(), b"another writer");
        // A failed publication cleans up only its own temporary file.
        assert!(write(directory.path(), &[b"cannot replace a directory"]).is_err());
        assert_eq!(std::fs::read(&occupied).unwrap(), b"another writer");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 2);
    }

    #[test]
    fn concurrent_writers_publish_whole_outputs() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("result");
        std::thread::scope(|scope| {
            for value in 0..8u8 {
                let output = &output;
                scope.spawn(move || write(output, &[&vec![value; 65536]]).unwrap());
            }
        });
        let result = std::fs::read(output).unwrap();
        assert_eq!(result.len(), 65536);
        assert!(result.iter().all(|value| *value == result[0]));
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
