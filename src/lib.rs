//! `ejsonkms` combines the [ejson](https://github.com/runlevel5/ejson-rs) library with
//! [AWS Key Management Service](https://aws.amazon.com/kms/) to simplify deployments on AWS.
//!
//! The EJSON private key is encrypted with KMS and stored inside the EJSON file as
//! `_private_key_enc`. Access to decrypt secrets can be controlled with IAM permissions
//! on the KMS key.
//!
//! ```no_run
//! # async fn example() -> Result<(), ejsonkms::EjsonKmsError> {
//! // Create a keypair whose private key is wrapped by a KMS key ...
//! let options = ejsonkms::KeygenOptions::default();
//! let keys = ejsonkms::keygen("alias/my-key", Some("us-east-1"), &options).await?;
//! std::fs::write("secrets.ejson", keys.to_document(ejson::FileFormat::Json)?)?;
//!
//! // ... and later decrypt the file; `None` uses the default AWS region chain.
//! let plaintext = ejsonkms::decrypt("secrets.ejson", None).await?;
//! let environment = ejsonkms::decrypt_env("secrets.ejson", None).await?;
//! # Ok(())
//! # }
//! ```
#![forbid(unsafe_code)]

mod kms;

use std::io::Read;
use std::path::Path;

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

    /// KMS could not encrypt or decrypt the private key.
    #[error(transparent)]
    Kms(#[from] KmsError),

    #[error(transparent)]
    Ejson(#[from] ejson::EjsonError),

    /// The file's `environment` section could not be used, for example
    /// because a key is not a valid variable name.
    #[error("could not load environment from file: {0}")]
    Env(ejson::env::EnvError),

    /// The file's `_kms_encryption_context` names a binding this version of
    /// ejsonkms doesn't know.
    #[error("unsupported _kms_encryption_context: {0:?}")]
    UnsupportedEncryptionContext(String),

    /// The file says its key is bound to `_public_key`, but has none.
    #[error("missing _public_key field")]
    MissingPublicKey,

    /// A file format this version of ejsonkms doesn't know how to read or
    /// write `_private_key_enc` in.
    #[error("unsupported file format: {0}")]
    UnsupportedFormat(FileFormat),
}

/// What went wrong talking to KMS.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum KmsError {
    /// The KMS `Decrypt` call failed; the payload is the AWS SDK's message
    /// (access denied, unknown key, no credentials, network failure, ...).
    #[error("unable to decrypt parameter: {0}")]
    Decrypt(String),

    /// The KMS `Encrypt` call failed; the payload is the AWS SDK's message.
    #[error("unable to encrypt parameter: {0}")]
    Encrypt(String),

    /// KMS answered a `Decrypt` call without a plaintext.
    #[error("KMS decrypt returned no plaintext")]
    NoPlaintext,

    /// KMS answered an `Encrypt` call without a ciphertext.
    #[error("KMS encrypt returned no ciphertext")]
    NoCiphertext,

    /// `_private_key_enc` decrypted to something that is not an ejson
    /// private key: it is not valid UTF-8.
    #[error("KMS decrypted key is not valid UTF-8")]
    KeyNotUtf8,
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
    /// The scheme the keypair is for.
    pub scheme: Scheme,
    /// Whether `private_key_enc` is bound to `public_key` through the KMS
    /// encryption context (see [`KeygenOptions::bind_public_key`]).
    pub bound_to_public_key: bool,
}

impl std::fmt::Debug for EjsonKmsKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EjsonKmsKeys")
            .field("public_key", &self.public_key)
            .field("private_key_enc", &self.private_key_enc)
            .field("private_key", &"[REDACTED]")
            .field("scheme", &self.scheme)
            .field("bound_to_public_key", &self.bound_to_public_key)
            .finish()
    }
}

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

/// The `_kms_encryption_context` value for a key bound to `_public_key`.
const BOUND_TO_PUBLIC_KEY: &str = "public_key";

impl EjsonKmsKeys {
    /// Render a new, empty secrets file holding these keys: `_public_key`
    /// and the KMS-encrypted `_private_key_enc`, in the given format, plus
    /// `_kms_encryption_context` when the key is bound to the public key.
    ///
    /// The unencrypted private key is not part of the document.
    pub fn to_document(&self, format: FileFormat) -> Result<String, EjsonKmsError> {
        let file = EjsonKmsFile {
            public_key: &self.public_key,
            private_key_enc: &self.private_key_enc,
            encryption_context: self.bound_to_public_key.then_some(BOUND_TO_PUBLIC_KEY),
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

/// How [`keygen`] should generate a keypair.
///
/// The default is a `v1` keypair, which every version of ejson and ejsonkms
/// (including the Go tools) can use.
///
/// ```
/// use ejsonkms::KeygenOptions;
///
/// let options = KeygenOptions::default().scheme(ejson::Scheme::V2);
/// ```
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct KeygenOptions {
    /// The key scheme: [`Scheme::V1`] (NaCl box, the default) or
    /// [`Scheme::V2`] (hybrid X25519 + ML-KEM-768, post-quantum). The Go
    /// tools cannot read `v2` files.
    pub scheme: Scheme,
    /// Bind the KMS-encrypted private key to the public key, using the KMS
    /// encryption context `ejsonkms_public_key = <public key>`.
    ///
    /// KMS then only decrypts the private key for a file that still has the
    /// same `_public_key`, so the wrapped key cannot be reused in another
    /// file, and IAM policies and CloudTrail can refer to the context. The
    /// file records this as `"_kms_encryption_context": "public_key"`.
    ///
    /// Off by default: ejsonkms before 3.0 and the Go tool cannot decrypt
    /// a file created this way.
    pub bind_public_key: bool,
}

impl KeygenOptions {
    /// Set the key scheme.
    #[must_use]
    pub fn scheme(mut self, scheme: Scheme) -> Self {
        self.scheme = scheme;
        self
    }

    /// Set whether to bind the encrypted private key to the public key; see
    /// [`bind_public_key`](Self::bind_public_key).
    #[must_use]
    pub fn bind_public_key(mut self, bind: bool) -> Self {
        self.bind_public_key = bind;
        self
    }
}

/// Generate keys and prepare an EJSON file with them.
///
/// The generated private key is encrypted with the given KMS key.
pub async fn keygen(
    kms_key_id: &str,
    aws_region: Option<&str>,
    options: &KeygenOptions,
) -> Result<EjsonKmsKeys, EjsonKmsError> {
    let scheme = options.scheme;
    let GeneratedKeypair {
        public_key,
        private_key,
        ..
    } = ejson::generate_keypair(scheme);

    let bound_to_public_key = options.bind_public_key;
    let private_key_enc = encrypt_private_key_with_kms(
        &private_key,
        kms_key_id,
        bound_to_public_key.then_some(public_key.as_str()),
        aws_region,
    )
    .await?;

    Ok(EjsonKmsKeys {
        public_key,
        private_key_enc,
        private_key,
        scheme,
        bound_to_public_key,
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
    ejson_file_path: impl AsRef<Path>,
    aws_region: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>, EjsonKmsError> {
    let file = EncryptedFile::open(ejson_file_path.as_ref(), aws_region).await?;

    let mut output = Zeroizing::new(Vec::new());
    ejson::decrypt(&file.data[..], &mut *output, file.key(), file.format)?;

    Ok(output)
}

/// Decrypt an EJSON/EYAML/ETOML file and return the values under its
/// `environment` key, obtaining the private key via KMS as [`decrypt`] does.
///
/// A file with no `environment` key, or one that is not a map, gives an
/// empty map rather than an error. Write the values as shell assignments
/// with [`ejson::env::export`].
pub async fn decrypt_env(
    ejson_file_path: impl AsRef<Path>,
    aws_region: Option<&str>,
) -> Result<SecretEnvMap, EjsonKmsError> {
    let file = EncryptedFile::open(ejson_file_path.as_ref(), aws_region).await?;

    let content =
        ejson::decrypt_bytes_typed(&file.data, file.key(), file.format, UnderscorePrefix::Keep)?;

    match ejson::env::extract_env(&content) {
        Ok(values) => Ok(values),
        Err(e) if e.is_missing_environment() => Ok(SecretEnvMap::new()),
        Err(e) => Err(EjsonKmsError::Env(e)),
    }
}

/// A secrets file read from disk, with its private key recovered via KMS.
struct EncryptedFile {
    data: Vec<u8>,
    format: FileFormat,
    private_key: Zeroizing<String>,
}

impl EncryptedFile {
    /// Read `path` and ask KMS to decrypt its `_private_key_enc`.
    async fn open(path: &Path, aws_region: Option<&str>) -> Result<Self, EjsonKmsError> {
        let format = detect_format(path)?;
        let data = read_file_checked(path)?;
        let wrapped = extract_private_key_enc(&data, format)?;
        let private_key = decrypt_private_key_with_kms(
            &wrapped.private_key_enc,
            wrapped.bound_public_key.as_deref(),
            aws_region,
        )
        .await?;

        Ok(Self {
            data,
            format,
            private_key,
        })
    }

    fn key(&self) -> KeySource<'_> {
        KeySource::PrivateKey(&self.private_key)
    }
}

/// Detect the file format from the file extension.
pub(crate) fn detect_format(file_path: &Path) -> Result<FileFormat, EjsonKmsError> {
    FileFormat::from_path(file_path)
        .map_err(ejson::EjsonError::from)
        .map_err(EjsonKmsError::from)
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
    if data.len() as u64 > max_size {
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
