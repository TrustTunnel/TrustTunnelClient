use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Replace a file atomically: write a temporary sibling, copy the original
/// permission mode onto it, then rename. The file must already exist — it
/// is never created.
pub fn replace_file_atomic(path: &str, content: &str) -> io::Result<()> {
    let path = Path::new(path);
    let metadata = std::fs::metadata(path)?;
    let dir = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "file path has no parent directory",
        )
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file path has no file name"))?;
    let (temp, mut file) = create_tempfile(dir, file_name)?;
    let result = file
        .write_all(content.as_bytes())
        .and_then(|()| std::fs::set_permissions(&temp, metadata.permissions()))
        .and_then(|()| std::fs::rename(&temp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

/// Reserve a new sibling temp file with `create_new`, so the path can never
/// be a pre-planted symlink or a collision with another writer.
fn create_tempfile(dir: &Path, file_name: &str) -> io::Result<(PathBuf, File)> {
    for attempt in 0..100u32 {
        let candidate = dir.join(format!(".{file_name}.{attempt}.tmp"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => return Ok((candidate, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to allocate a temporary file name",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_content_and_preserves_mode() {
        let dir =
            std::env::temp_dir().join(format!("subscription-write-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "old").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        replace_file_atomic(path.to_str().unwrap(), "new").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_file_is_an_error_not_a_creation() {
        let dir =
            std::env::temp_dir().join(format!("subscription-write-missing-{}", std::process::id()));
        let path = dir.join("does-not-exist.toml");
        assert!(replace_file_atomic(path.to_str().unwrap(), "x").is_err());
        assert!(!path.exists());
    }

    #[test]
    fn stale_temp_file_is_skipped_not_overwritten() {
        let dir =
            std::env::temp_dir().join(format!("subscription-write-stale-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "old").unwrap();
        let stale = dir.join(".config.toml.0.tmp");
        std::fs::write(&stale, "stale").unwrap();
        replace_file_atomic(path.to_str().unwrap(), "new").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        assert_eq!(std::fs::read_to_string(&stale).unwrap(), "stale");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn preexisting_temp_symlink_is_not_followed() {
        let dir =
            std::env::temp_dir().join(format!("subscription-write-symlink-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "old").unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, "victim").unwrap();
        std::os::unix::fs::symlink(&victim, dir.join(".config.toml.0.tmp")).unwrap();
        replace_file_atomic(path.to_str().unwrap(), "new").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "victim");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
