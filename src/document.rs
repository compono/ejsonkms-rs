//! Reading and writing the ejsonkms fields of a secrets file: `_public_key`,
//! `_private_key_enc` and `_kms_encryption_context`.

use std::io::Read;
use std::path::Path;

use ejson::FileFormat;
use serde::{Deserialize, Serialize};

use crate::EjsonKmsError;

/// The `_kms_encryption_context` value for a key bound to `_public_key`.
const BOUND_TO_PUBLIC_KEY: &str = "public_key";

#[derive(Serialize)]
struct EjsonKmsFile<'a> {
    #[serde(rename = "_public_key")]
    public_key: &'a str,
    #[serde(rename = "_private_key_enc")]
    private_key_enc: &'a str,
    #[serde(
        rename = "_kms_encryption_context",
        skip_serializing_if = "Option::is_none"
    )]
    encryption_context: Option<&'a str>,
}

/// Render a new, empty secrets file: `_public_key`, `_private_key_enc` and,
/// when the key is bound to the public key, `_kms_encryption_context`.
pub(crate) fn render(
    public_key: &str,
    private_key_enc: &str,
    bound_to_public_key: bool,
    format: FileFormat,
) -> Result<String, EjsonKmsError> {
    let file = EjsonKmsFile {
        public_key,
        private_key_enc,
        encryption_context: bound_to_public_key.then_some(BOUND_TO_PUBLIC_KEY),
    };
    match format {
        FileFormat::Json => serde_json::to_string_pretty(&file).map_err(EjsonKmsError::json),
        FileFormat::Yaml => serde_norway::to_string(&file).map_err(EjsonKmsError::yaml),
        FileFormat::Toml => toml::to_string(&file).map_err(EjsonKmsError::toml),
        // `FileFormat` may gain formats in a minor release of ejson.
        other => Err(EjsonKmsError::UnsupportedFormat(other)),
    }
}

/// Detect the file format from the file extension.
pub(crate) fn detect_format(file_path: &Path) -> Result<FileFormat, EjsonKmsError> {
    Ok(FileFormat::from_path(file_path).map_err(ejson::EjsonError::from)?)
}

/// Read a file, failing once more than `ejson::MAX_FILE_SIZE` bytes have
/// been read.
///
/// The limit is enforced on the bytes actually read rather than on the size
/// reported beforehand, so a file that grows (or a device or pipe, which
/// report no size) cannot be buffered without bound.
pub(crate) fn read_file_checked(file_path: &Path) -> Result<Vec<u8>, EjsonKmsError> {
    read_limited(std::fs::File::open(file_path)?, ejson::MAX_FILE_SIZE)
}

fn read_limited(reader: impl Read, max_size: u64) -> Result<Vec<u8>, EjsonKmsError> {
    let mut data = Vec::new();
    reader.take(max_size + 1).read_to_end(&mut data)?;
    // A length that doesn't fit in `u64` is certainly over the limit.
    if u64::try_from(data.len()).map_or(true, |len| len > max_size) {
        return Err(EjsonKmsError::Ejson(ejson::EjsonError::FileTooLarge));
    }
    Ok(data)
}

#[derive(Deserialize)]
struct EjsonKmsFileFields {
    #[serde(rename = "_public_key", default)]
    public_key: Option<String>,
    #[serde(rename = "_private_key_enc", default)]
    private_key_enc: Option<String>,
    #[serde(rename = "_kms_encryption_context", default)]
    encryption_context: Option<String>,
}

/// The KMS-encrypted private key found in a file.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct WrappedKey {
    /// `_private_key_enc`.
    pub(crate) private_key_enc: String,
    /// The file's `_public_key`, when the file says the key is bound to it.
    pub(crate) bound_public_key: Option<String>,
}

/// Extract the `_private_key_enc` field, and what it is bound to, from raw
/// EJSON/EYAML/ETOML file data.
pub(crate) fn extract_private_key_enc(
    data: &[u8],
    format: FileFormat,
) -> Result<WrappedKey, EjsonKmsError> {
    let fields: EjsonKmsFileFields = match format {
        FileFormat::Json => serde_json::from_slice(data).map_err(EjsonKmsError::json)?,
        FileFormat::Yaml => serde_norway::from_slice(data).map_err(EjsonKmsError::yaml)?,
        FileFormat::Toml => {
            toml::from_str(std::str::from_utf8(data)?).map_err(EjsonKmsError::toml)?
        }
        // `FileFormat` may gain formats in a minor release of ejson.
        other => return Err(EjsonKmsError::UnsupportedFormat(other)),
    };

    let private_key_enc = fields
        .private_key_enc
        .filter(|key| !key.is_empty())
        .ok_or(EjsonKmsError::MissingPrivateKeyEnc)?;

    let bound_public_key = match fields.encryption_context.as_deref() {
        None => None,
        Some(BOUND_TO_PUBLIC_KEY) => Some(
            fields
                .public_key
                .filter(|key| !key.is_empty())
                .ok_or(EjsonKmsError::MissingPublicKey)?,
        ),
        Some(other) => {
            return Err(EjsonKmsError::UnsupportedEncryptionContext(
                other.to_string(),
            ));
        }
    };

    Ok(WrappedKey {
        private_key_enc,
        bound_public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_private_key_enc() {
        let data = br#"{"_public_key": "abc", "_private_key_enc": "encrypted"}"#;
        assert_eq!(
            extract_private_key_enc(data, FileFormat::Json)
                .unwrap()
                .private_key_enc,
            "encrypted"
        );
    }

    #[test]
    fn test_extract_private_key_enc_missing() {
        let data = br#"{"_public_key": "abc"}"#;
        let err = extract_private_key_enc(data, FileFormat::Json).unwrap_err();
        assert!(err.to_string().contains("missing _private_key_enc"));
    }

    #[test]
    fn test_extract_private_key_enc_empty() {
        let data = br#"{"_public_key": "abc", "_private_key_enc": ""}"#;
        let err = extract_private_key_enc(data, FileFormat::Json).unwrap_err();
        assert!(err.to_string().contains("missing _private_key_enc"));
    }

    #[test]
    fn test_extract_private_key_enc_yaml() {
        let data = b"_public_key: abc\n_private_key_enc: encrypted\n";
        assert_eq!(
            extract_private_key_enc(data, FileFormat::Yaml)
                .unwrap()
                .private_key_enc,
            "encrypted"
        );

        let missing = b"_public_key: abc\n";
        assert!(matches!(
            extract_private_key_enc(missing, FileFormat::Yaml),
            Err(EjsonKmsError::MissingPrivateKeyEnc)
        ));
    }

    #[test]
    fn test_extract_private_key_enc_toml() {
        let data = b"_public_key = \"abc\"\n_private_key_enc = \"encrypted\"\n";
        assert_eq!(
            extract_private_key_enc(data, FileFormat::Toml)
                .unwrap()
                .private_key_enc,
            "encrypted"
        );

        let missing = b"_public_key = \"abc\"\n";
        assert!(matches!(
            extract_private_key_enc(missing, FileFormat::Toml),
            Err(EjsonKmsError::MissingPrivateKeyEnc)
        ));
    }

    #[test]
    fn test_extract_private_key_enc_from_testdata() {
        let data = std::fs::read("testdata/test.ejson").unwrap();
        let key = extract_private_key_enc(&data, FileFormat::Json)
            .unwrap()
            .private_key_enc;
        assert!(key.starts_with("S2Fybjphd3M6a21z"));
    }

    #[test]
    fn test_extract_private_key_enc_missing_in_testdata() {
        let data = std::fs::read("testdata/test_no_private_key.ejson").unwrap();
        assert!(matches!(
            extract_private_key_enc(&data, FileFormat::Json),
            Err(EjsonKmsError::MissingPrivateKeyEnc)
        ));
    }

    #[test]
    fn test_parser_errors_keep_their_message() {
        let source = serde_json::from_slice::<serde_json::Value>(b"{").unwrap_err();
        let expected = format!("json error: {source}");
        let err = extract_private_key_enc(b"{", FileFormat::Json).unwrap_err();
        assert!(matches!(err, EjsonKmsError::Json(_)));
        assert_eq!(err.to_string(), expected);

        let err = extract_private_key_enc(b"a: [", FileFormat::Yaml).unwrap_err();
        assert!(matches!(err, EjsonKmsError::Yaml(_)));
        assert!(err.to_string().starts_with("yaml error: "), "{err}");

        let err = extract_private_key_enc(b"a = ", FileFormat::Toml).unwrap_err();
        assert!(matches!(err, EjsonKmsError::Toml(_)));
        assert!(err.to_string().starts_with("toml error: "), "{err}");

        let source =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, "!").unwrap_err();
        let err = EjsonKmsError::base64(source.clone());
        assert_eq!(err.to_string(), format!("base64 decode error: {source}"));
    }

    #[test]
    fn test_extract_encryption_context() {
        // No marker: the key is not bound to anything.
        let legacy = br#"{"_public_key": "abc", "_private_key_enc": "encrypted"}"#;
        assert_eq!(
            extract_private_key_enc(legacy, FileFormat::Json).unwrap(),
            WrappedKey {
                private_key_enc: "encrypted".to_string(),
                bound_public_key: None,
            }
        );

        let bound = br#"{"_public_key": "abc", "_private_key_enc": "encrypted", "_kms_encryption_context": "public_key"}"#;
        assert_eq!(
            extract_private_key_enc(bound, FileFormat::Json).unwrap(),
            WrappedKey {
                private_key_enc: "encrypted".to_string(),
                bound_public_key: Some("abc".to_string()),
            }
        );

        let yaml =
            b"_public_key: abc\n_private_key_enc: encrypted\n_kms_encryption_context: public_key\n";
        assert_eq!(
            extract_private_key_enc(yaml, FileFormat::Yaml)
                .unwrap()
                .bound_public_key
                .as_deref(),
            Some("abc")
        );

        let toml = b"_public_key = \"abc\"\n_private_key_enc = \"encrypted\"\n_kms_encryption_context = \"public_key\"\n";
        assert_eq!(
            extract_private_key_enc(toml, FileFormat::Toml)
                .unwrap()
                .bound_public_key
                .as_deref(),
            Some("abc")
        );

        let unknown = br#"{"_public_key": "abc", "_private_key_enc": "encrypted", "_kms_encryption_context": "v9"}"#;
        let err = extract_private_key_enc(unknown, FileFormat::Json).unwrap_err();
        assert!(matches!(
            &err,
            EjsonKmsError::UnsupportedEncryptionContext(name) if name == "v9"
        ));
        assert_eq!(
            err.to_string(),
            r#"unsupported _kms_encryption_context: "v9""#
        );

        let no_public_key =
            br#"{"_private_key_enc": "encrypted", "_kms_encryption_context": "public_key"}"#;
        assert!(matches!(
            extract_private_key_enc(no_public_key, FileFormat::Json),
            Err(EjsonKmsError::MissingPublicKey)
        ));
    }

    #[test]
    fn test_read_limited_enforces_the_limit_on_bytes_read() {
        assert_eq!(read_limited(&b"12345"[..], 5).unwrap(), b"12345");
        assert!(matches!(
            read_limited(&b"123456"[..], 5),
            Err(EjsonKmsError::Ejson(ejson::EjsonError::FileTooLarge))
        ));
        // A source with no size to check up front.
        assert!(matches!(
            read_limited(std::io::repeat(0), 1024),
            Err(EjsonKmsError::Ejson(ejson::EjsonError::FileTooLarge))
        ));
    }

    #[test]
    fn test_unsupported_format_error_names_the_format() {
        let err = EjsonKmsError::UnsupportedFormat(FileFormat::Toml);
        assert_eq!(err.to_string(), "unsupported file format: TOML");
    }

    #[test]
    fn test_ejson_errors_keep_their_message() {
        // ejson 2.0 errors carry no "format error:"-style prefixes, and
        // ejsonkms passes them through unchanged.
        let err = detect_format(Path::new("secrets.txt")).unwrap_err();
        assert!(matches!(
            err,
            EjsonKmsError::Ejson(ejson::EjsonError::FileFormat(_))
        ));
        assert_eq!(err.to_string(), "unsupported file extension: txt");
    }

    #[test]
    fn test_detect_format() {
        assert_eq!(
            detect_format(Path::new("a.ejson")).unwrap(),
            FileFormat::Json
        );
        assert_eq!(
            detect_format(Path::new("a.eyaml")).unwrap(),
            FileFormat::Yaml
        );
        assert_eq!(
            detect_format(Path::new("a.etoml")).unwrap(),
            FileFormat::Toml
        );
        assert!(detect_format(Path::new("a.txt")).is_err());
    }
}
