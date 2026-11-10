//! `ejsonkms` combines the [ejson](https://github.com/runlevel5/ejson-rs) library with
//! [AWS Key Management Service](https://aws.amazon.com/kms/) to simplify deployments on AWS.
//!
//! The EJSON private key is encrypted with KMS and stored inside the EJSON file as
//! `_private_key_enc`. Access to decrypt secrets can be controlled with IAM permissions
//! on the KMS key.
#![forbid(unsafe_code)]

mod kms;

use ejson::env::SecretEnvMap;
use ejson::{FileFormat, GeneratedKeypair, KeySource, Scheme, UnderscorePrefix};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

pub(crate) use kms::{decrypt_private_key_with_kms, encrypt_private_key_with_kms};

/// Errors that can occur during ejsonkms operations.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum EjsonKmsError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The file could not be read or written as JSON.
    #[error("json error: {0}")]
    Json(SourceError),

    /// The file could not be read or written as YAML.
    #[error("yaml error: {0}")]
    Yaml(SourceError),

    /// The file could not be read or written as TOML.
    #[error("toml error: {0}")]
    Toml(SourceError),

    #[error("utf-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("missing _private_key_enc field")]
    MissingPrivateKeyEnc,

    /// `_private_key_enc` is not valid base64.
    #[error("base64 decode error: {0}")]
    Base64(SourceError),

    #[error("{0}")]
    Kms(String),

    #[error(transparent)]
    Ejson(#[from] ejson::EjsonError),

    #[error("{0}")]
    Env(String),

    /// A file format this version of ejsonkms doesn't know how to read or
    /// write `_private_key_enc` in.
    #[error("unsupported file format: {0}")]
    UnsupportedFormat(FileFormat),
}

impl EjsonKmsError {
    pub(crate) fn json(err: serde_json::Error) -> Self {
        Self::Json(SourceError::new(err))
    }

    pub(crate) fn yaml(err: serde_norway::Error) -> Self {
        Self::Yaml(SourceError::new(err))
    }

    pub(crate) fn toml(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Toml(SourceError::new(err))
    }

    pub(crate) fn base64(err: base64::DecodeError) -> Self {
        Self::Base64(SourceError::new(err))
    }
}

/// An error from one of the parsers or encoders ejsonkms uses.
///
/// The concrete type is hidden so that those crates are not part of the
/// ejsonkms API; upgrading one of them is then not a breaking change here.
/// It displays the underlying error's message.
pub struct SourceError(Box<dyn std::error::Error + Send + Sync + 'static>);

impl SourceError {
    fn new(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self(Box::new(err))
    }
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::fmt::Debug for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for SourceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

/// Keys used in an EjsonKms file.
///
/// Security: the private key is zeroized from memory when the struct is
/// dropped, and the `Debug` implementation redacts it.
#[non_exhaustive]
pub struct EjsonKmsKeys {
    /// The public key, stored in the file as `_public_key`.
    pub public_key: String,
    /// The private key encrypted with KMS and base64-encoded, stored in the
    /// file as `_private_key_enc`.
    pub private_key_enc: String,
    /// The unencrypted private key. Nothing needs it once the file is
    /// written; keep it out of logs.
    pub private_key: Zeroizing<String>,
}

impl std::fmt::Debug for EjsonKmsKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EjsonKmsKeys")
            .field("public_key", &self.public_key)
            .field("private_key_enc", &self.private_key_enc)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Serialize)]
struct EjsonKmsFile<'a> {
    #[serde(rename = "_public_key")]
    public_key: &'a str,
    #[serde(rename = "_private_key_enc")]
    private_key_enc: &'a str,
}

impl EjsonKmsKeys {
    /// Render a new, empty secrets file holding these keys: `_public_key`
    /// and the KMS-encrypted `_private_key_enc`, in the given format.
    ///
    /// The unencrypted private key is not part of the document.
    pub fn to_document(&self, format: FileFormat) -> Result<String, EjsonKmsError> {
        let file = EjsonKmsFile {
            public_key: &self.public_key,
            private_key_enc: &self.private_key_enc,
        };
        match format {
            FileFormat::Json => serde_json::to_string_pretty(&file).map_err(EjsonKmsError::json),
            FileFormat::Yaml => serde_norway::to_string(&file).map_err(EjsonKmsError::yaml),
            FileFormat::Toml => toml::to_string(&file).map_err(EjsonKmsError::toml),
            // `FileFormat` may gain formats in a minor release of ejson.
            other => Err(EjsonKmsError::UnsupportedFormat(other)),
        }
    }
}

/// Generate keys and prepare an EJSON file with them.
///
/// The generated private key is encrypted with the given KMS key.
pub async fn keygen(kms_key_id: &str, aws_region: &str) -> Result<EjsonKmsKeys, EjsonKmsError> {
    let GeneratedKeypair {
        public_key,
        private_key,
        ..
    } = ejson::generate_keypair(Scheme::V1);

    let private_key_enc =
        encrypt_private_key_with_kms(&private_key, kms_key_id, aws_region).await?;

    Ok(EjsonKmsKeys {
        public_key,
        private_key_enc,
        private_key,
    })
}

/// Decrypt an EJSON/EYAML/ETOML file, obtaining the private key from the
/// embedded `_private_key_enc` field via KMS.
///
/// The file format is auto-detected from the file extension:
/// - `.ejson` or `.json` -> JSON format
/// - `.etoml` or `.toml` -> TOML format
/// - `.eyaml`, `.eyml`, `.yaml`, or `.yml` -> YAML format
///
/// The decrypted document is wrapped in [`Zeroizing`], so it is wiped from
/// memory when dropped.
pub async fn decrypt(
    ejson_file_path: &str,
    aws_region: &str,
) -> Result<Zeroizing<Vec<u8>>, EjsonKmsError> {
    let format = detect_format(ejson_file_path)?;
    let data = read_file_checked(ejson_file_path)?;

    let private_key_enc = extract_private_key_enc(&data, format)?;

    let kms_decrypted_private_key =
        decrypt_private_key_with_kms(&private_key_enc, aws_region).await?;

    let mut output = Zeroizing::new(Vec::new());
    ejson::decrypt(
        &data[..],
        &mut *output,
        KeySource::PrivateKey(&kms_decrypted_private_key),
        format,
    )?;

    Ok(output)
}

/// Decrypt an EJSON/EYAML/ETOML file and return the values under its
/// `environment` key, obtaining the private key via KMS as [`decrypt`] does.
///
/// A file with no `environment` key, or one that is not a map, gives an
/// empty map rather than an error. Write the values as shell assignments
/// with [`ejson::env::export`].
pub async fn decrypt_env(
    ejson_file_path: &str,
    aws_region: &str,
) -> Result<SecretEnvMap, EjsonKmsError> {
    let format = detect_format(ejson_file_path)?;
    let data = read_file_checked(ejson_file_path)?;

    let private_key_enc = extract_private_key_enc(&data, format)?;

    let kms_decrypted_private_key =
        decrypt_private_key_with_kms(&private_key_enc, aws_region).await?;

    let content = ejson::decrypt_bytes_typed(
        &data,
        KeySource::PrivateKey(&kms_decrypted_private_key),
        format,
        UnderscorePrefix::Keep,
    )?;

    match ejson::env::extract_env(&content) {
        Ok(values) => Ok(values),
        Err(e) if e.is_missing_environment() => Ok(SecretEnvMap::new()),
        Err(e) => Err(EjsonKmsError::Env(format!(
            "could not load environment from file: {e}"
        ))),
    }
}

/// Detect the file format from the file extension.
pub(crate) fn detect_format(file_path: &str) -> Result<FileFormat, EjsonKmsError> {
    FileFormat::from_path(file_path)
        .map_err(ejson::EjsonError::from)
        .map_err(EjsonKmsError::from)
}

/// Read a file, rejecting anything larger than `ejson::MAX_FILE_SIZE` before
/// loading it into memory.
pub(crate) fn read_file_checked(file_path: &str) -> Result<Vec<u8>, EjsonKmsError> {
    let metadata = std::fs::metadata(file_path)?;
    if metadata.len() > ejson::MAX_FILE_SIZE {
        return Err(EjsonKmsError::Ejson(ejson::EjsonError::FileTooLarge));
    }
    Ok(std::fs::read(file_path)?)
}

#[derive(Deserialize)]
struct EjsonKmsFileFields {
    #[serde(rename = "_private_key_enc", default)]
    private_key_enc: Option<String>,
}

/// Extract the `_private_key_enc` field from raw EJSON/EYAML/ETOML file data.
pub(crate) fn extract_private_key_enc(
    data: &[u8],
    format: FileFormat,
) -> Result<String, EjsonKmsError> {
    let fields: EjsonKmsFileFields = match format {
        FileFormat::Json => serde_json::from_slice(data).map_err(EjsonKmsError::json)?,
        FileFormat::Yaml => serde_norway::from_slice(data).map_err(EjsonKmsError::yaml)?,
        FileFormat::Toml => {
            toml::from_str(std::str::from_utf8(data)?).map_err(EjsonKmsError::toml)?
        }
        // `FileFormat` may gain formats in a minor release of ejson.
        other => return Err(EjsonKmsError::UnsupportedFormat(other)),
    };

    match fields.private_key_enc {
        Some(key) if !key.is_empty() => Ok(key),
        _ => Err(EjsonKmsError::MissingPrivateKeyEnc),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_private_key_enc() {
        let data = br#"{"_public_key": "abc", "_private_key_enc": "encrypted"}"#;
        assert_eq!(
            extract_private_key_enc(data, FileFormat::Json).unwrap(),
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
            extract_private_key_enc(data, FileFormat::Yaml).unwrap(),
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
            extract_private_key_enc(data, FileFormat::Toml).unwrap(),
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
        let key = extract_private_key_enc(&data, FileFormat::Json).unwrap();
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
    fn test_unsupported_format_error_names_the_format() {
        let err = EjsonKmsError::UnsupportedFormat(FileFormat::Toml);
        assert_eq!(err.to_string(), "unsupported file format: TOML");
    }

    #[test]
    fn test_ejson_errors_keep_their_message() {
        // ejson 2.0 errors carry no "format error:"-style prefixes, and
        // ejsonkms passes them through unchanged.
        let err = detect_format("secrets.txt").unwrap_err();
        assert!(matches!(
            err,
            EjsonKmsError::Ejson(ejson::EjsonError::FileFormat(_))
        ));
        assert_eq!(err.to_string(), "unsupported file extension: txt");
    }

    #[test]
    fn test_detect_format() {
        assert_eq!(detect_format("a.ejson").unwrap(), FileFormat::Json);
        assert_eq!(detect_format("a.eyaml").unwrap(), FileFormat::Yaml);
        assert_eq!(detect_format("a.etoml").unwrap(), FileFormat::Toml);
        assert!(detect_format("a.txt").is_err());
    }
}
