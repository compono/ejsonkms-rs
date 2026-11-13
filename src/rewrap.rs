//! Replacing the KMS-encrypted private key in an existing secrets file.

use std::fs;
use std::io::Write;
use std::mem::DropGuard;
use std::path::Path;

use ejson::FileFormat;
use thiserror::Error as ThisError;

use crate::document::{BOUND_TO_PUBLIC_KEY, WrappedKey, extract_private_key_enc};
use crate::{Error, KeyBinding, Result};

/// Why a secrets file could not be updated with a re-encrypted private key.
#[derive(ThisError, Debug)]
#[non_exhaustive]
pub enum RewrapError {
    /// The file is not valid UTF-8, so it cannot be edited as text.
    #[error("the file is not valid UTF-8")]
    NotUtf8,

    /// The `_private_key_enc` value does not appear in the file's text
    /// exactly once (for example because it is written with escapes), so
    /// it cannot be replaced safely.
    #[error("the _private_key_enc value was not found exactly once in the file's text")]
    KeyNotFound,

    /// The file is laid out in a way `_kms_encryption_context` cannot be
    /// added to automatically (for example YAML in flow style). Reformat
    /// the file with one key per line and try again.
    #[error("could not add _kms_encryption_context to a file laid out like this")]
    UnsupportedLayout,

    /// A key bound to its public key cannot be turned back into an unbound
    /// one.
    #[error("the key is bound to its public key and cannot be unbound")]
    CannotUnbind,

    /// The file changed on disk while its key was being re-encrypted.
    #[error("the file changed while it was being rewrapped")]
    FileChanged,
}

/// Return `data` with its `_private_key_enc` replaced by `new_private_key_enc`
/// and, if `add_binding`, a `_kms_encryption_context` marker added.
///
/// Everything else in the file (layout, comments, the encrypted values) is
/// kept byte for byte. The result is parsed again and checked before it is
/// returned, so a file that this textual edit would damage is rejected
/// rather than written.
pub(crate) fn rewrite(
    data: &[u8],
    format: FileFormat,
    current: &WrappedKey,
    new_private_key_enc: &str,
    add_binding: bool,
) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(data).map_err(|_| RewrapError::NotUtf8)?;

    let old = current.private_key_enc.as_str();
    let mut occurrences = text.match_indices(old);
    let (Some((start, _)), None) = (occurrences.next(), occurrences.next()) else {
        return Err(RewrapError::KeyNotFound.into());
    };
    let value_end = start + old.len();

    let mut updated = String::with_capacity(text.len() + new_private_key_enc.len());
    updated.push_str(&text[..start]);
    updated.push_str(new_private_key_enc);

    let rest = &text[value_end..];
    if add_binding {
        let line_start = text[..start].rfind('\n').map_or(0, |newline| newline + 1);
        let indent: String = text[line_start..]
            .chars()
            .take_while(|c| *c == ' ' || *c == '\t')
            .collect();
        // Where the new entry goes: right after the value's closing quote in
        // JSON, at the end of the value's line otherwise.
        let line_end = rest.find('\n').unwrap_or(rest.len());
        let (before, line_end) = match rest[..line_end].strip_suffix('\r') {
            // A `\r\n` line ending stays together, and is reused.
            Some(line) => (line.len(), "\r\n"),
            None => (line_end, "\n"),
        };
        let (before, entry) = match format {
            FileFormat::Json => {
                if !rest.starts_with('"') {
                    return Err(RewrapError::UnsupportedLayout.into());
                }
                (
                    1,
                    format!(
                        ",{line_end}{indent}\"_kms_encryption_context\": \"{BOUND_TO_PUBLIC_KEY}\""
                    ),
                )
            }
            FileFormat::Yaml => (
                before,
                format!("{line_end}{indent}_kms_encryption_context: {BOUND_TO_PUBLIC_KEY}"),
            ),
            FileFormat::Toml => (
                before,
                format!("{line_end}{indent}_kms_encryption_context = \"{BOUND_TO_PUBLIC_KEY}\""),
            ),
            other => return Err(Error::UnsupportedFormat(other)),
        };
        updated.push_str(&rest[..before]);
        updated.push_str(&entry);
        updated.push_str(&rest[before..]);
    } else {
        updated.push_str(rest);
    }

    // Check the edit by reading the result back the way `decrypt` would.
    let expected_binding = if add_binding {
        KeyBinding::PublicKey
    } else {
        current.binding
    };
    let reread = extract_private_key_enc(updated.as_bytes(), format)
        .map_err(|_| RewrapError::UnsupportedLayout)?;
    if reread.private_key_enc != new_private_key_enc
        || reread.binding != expected_binding
        || reread.public_key != current.public_key
    {
        return Err(RewrapError::UnsupportedLayout.into());
    }

    Ok(updated.into_bytes())
}

/// Replace `path` with `data` through a temporary file in the same
/// directory, keeping the original's permissions.
///
/// The file holds the only copy of the wrapped private key, so it must never
/// be left half-written.
pub(crate) fn replace_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let permissions = fs::metadata(path)?.permissions();
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let mut name = std::ffi::OsString::from(".");
    name.push(path.file_name().unwrap_or_default());
    name.push(format!(".rewrap-{}.tmp", std::process::id()));
    let temp_path = parent.join(name);

    let temp = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)?;

    // Remove the temporary file unless the rename succeeds, on an error and
    // on a panic alike.
    let temp_path = DropGuard::new(temp_path, |temp_path| {
        let _ = fs::remove_file(temp_path);
    });
    // Declared after the guard so that the file is closed before the guard
    // removes it: Windows may refuse to delete a file that is still open.
    let mut temp = temp;

    temp.set_permissions(permissions)?;
    temp.write_all(data)?;
    temp.sync_all()?;
    drop(temp);
    fs::rename(&*temp_path, path)?;
    DropGuard::dismiss(temp_path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &str = "b2xkLXdyYXBwZWQta2V5";
    const NEW: &str = "bmV3LXdyYXBwZWQta2V5";

    fn rewrite_text(text: &str, format: FileFormat, add_binding: bool) -> Result<String> {
        let current = extract_private_key_enc(text.as_bytes(), format).unwrap();
        rewrite(text.as_bytes(), format, &current, NEW, add_binding)
            .map(|data| String::from_utf8(data).unwrap())
    }

    #[test]
    fn test_rewrite_replaces_only_the_wrapped_key() {
        let json = format!(
            "{{\n  \"_public_key\": \"abc\",\n  \"_private_key_enc\": \"{OLD}\",\n  \"secret\": \"EJ[1:x:y:z]\"\n}}\n"
        );
        assert_eq!(
            rewrite_text(&json, FileFormat::Json, false).unwrap(),
            json.replace(OLD, NEW)
        );

        let yaml = format!(
            "# keep this comment\n_public_key: abc\n_private_key_enc: {OLD}\nsecret: EJ[1:x:y:z]\n"
        );
        assert_eq!(
            rewrite_text(&yaml, FileFormat::Yaml, false).unwrap(),
            yaml.replace(OLD, NEW)
        );

        let toml = format!(
            "# keep this comment\n_public_key = \"abc\"\n_private_key_enc = \"{OLD}\"\n\n[environment]\nsecret = \"EJ[1:x:y:z]\"\n"
        );
        assert_eq!(
            rewrite_text(&toml, FileFormat::Toml, false).unwrap(),
            toml.replace(OLD, NEW)
        );
    }

    #[test]
    fn test_rewrite_adds_the_binding_marker() {
        // Pretty JSON, key in the middle and key last.
        let json = format!(
            "{{\n  \"_public_key\": \"abc\",\n  \"_private_key_enc\": \"{OLD}\",\n  \"secret\": \"x\"\n}}\n"
        );
        assert_eq!(
            rewrite_text(&json, FileFormat::Json, true).unwrap(),
            format!(
                "{{\n  \"_public_key\": \"abc\",\n  \"_private_key_enc\": \"{NEW}\",\n  \"_kms_encryption_context\": \"public_key\",\n  \"secret\": \"x\"\n}}\n"
            )
        );
        let json =
            format!("{{\n  \"_public_key\": \"abc\",\n  \"_private_key_enc\": \"{OLD}\"\n}}\n");
        assert_eq!(
            rewrite_text(&json, FileFormat::Json, true).unwrap(),
            format!(
                "{{\n  \"_public_key\": \"abc\",\n  \"_private_key_enc\": \"{NEW}\",\n  \"_kms_encryption_context\": \"public_key\"\n}}\n"
            )
        );
        // Compact JSON stays valid.
        let json =
            format!("{{\"_public_key\":\"abc\",\"_private_key_enc\":\"{OLD}\",\"s\":\"x\"}}");
        let updated = rewrite_text(&json, FileFormat::Json, true).unwrap();
        let parsed = extract_private_key_enc(updated.as_bytes(), FileFormat::Json).unwrap();
        assert_eq!(parsed.binding, KeyBinding::PublicKey);

        let yaml = format!("_public_key: abc\n_private_key_enc: \"{OLD}\" # wrapped\nsecret: x\n");
        assert_eq!(
            rewrite_text(&yaml, FileFormat::Yaml, true).unwrap(),
            format!(
                "_public_key: abc\n_private_key_enc: \"{NEW}\" # wrapped\n_kms_encryption_context: public_key\nsecret: x\n"
            )
        );

        let toml = format!(
            "_public_key = \"abc\"\r\n_private_key_enc = \"{OLD}\"\r\n\r\n[environment]\r\nsecret = \"x\"\r\n"
        );
        assert_eq!(
            rewrite_text(&toml, FileFormat::Toml, true).unwrap(),
            format!(
                "_public_key = \"abc\"\r\n_private_key_enc = \"{NEW}\"\r\n_kms_encryption_context = \"public_key\"\r\n\r\n[environment]\r\nsecret = \"x\"\r\n"
            )
        );

        // No trailing newline.
        let yaml = format!("_public_key: abc\n_private_key_enc: {OLD}");
        assert_eq!(
            rewrite_text(&yaml, FileFormat::Yaml, true).unwrap(),
            format!(
                "_public_key: abc\n_private_key_enc: {NEW}\n_kms_encryption_context: public_key"
            )
        );
    }

    #[test]
    fn test_rewrite_rejects_what_it_cannot_edit_safely() {
        // YAML flow style: a marker on the next line would not be part of
        // the mapping.
        let yaml = format!("{{_public_key: abc, _private_key_enc: {OLD}}}\n");
        assert!(matches!(
            rewrite_text(&yaml, FileFormat::Yaml, true),
            Err(Error::Rewrap(RewrapError::UnsupportedLayout))
        ));
        // ... but replacing the key alone is fine there.
        assert_eq!(
            rewrite_text(&yaml, FileFormat::Yaml, false).unwrap(),
            yaml.replace(OLD, NEW)
        );

        // The same text twice: which one is the key?
        let json = format!(
            "{{\"_public_key\":\"abc\",\"_private_key_enc\":\"{OLD}\",\"copy\":\"{OLD}\"}}"
        );
        assert!(matches!(
            rewrite_text(&json, FileFormat::Json, false),
            Err(Error::Rewrap(RewrapError::KeyNotFound))
        ));

        // Written with an escape, so the decoded value is not in the text.
        let json = "{\"_public_key\":\"abc\",\"_private_key_enc\":\"b2xk\\u002dkey\"}";
        assert!(matches!(
            rewrite_text(json, FileFormat::Json, false),
            Err(Error::Rewrap(RewrapError::KeyNotFound))
        ));
    }

    #[test]
    fn test_replace_file_keeps_permissions_and_leaves_no_temp_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("secrets.ejson");
        fs::write(&path, "old").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        }

        replace_file(&path, b"new").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"new");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o640
            );
        }
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
