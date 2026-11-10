//! The errors ejsonkms reports.

use std::path::PathBuf;

use ejson::FileFormat;
use thiserror::Error;

/// Errors that can occur during ejsonkms operations.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// The secrets file could not be read.
    #[error("{}: {source}", path.display())]
    ReadFile {
        /// The file that was being read.
        path: PathBuf,
        /// Why it could not be read.
        source: std::io::Error,
    },

    /// Some other input or output failed, for example writing a result.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The file could not be read or written as JSON.
    #[error("json error: {0}")]
    Json(SourceError),

    /// The file could not be read or written as YAML.
    #[error("yaml error: {0}")]
    Yaml(SourceError),

    /// The file could not be read or written as TOML (or, being TOML, is not
    /// valid UTF-8).
    #[error("toml error: {0}")]
    Toml(SourceError),

    /// The file has no `_private_key_enc`, or it is empty, so there is no
    /// key to ask KMS for.
    #[error("missing _private_key_enc field")]
    MissingPrivateKeyEnc,

    /// `_private_key_enc` is not valid base64.
    #[error("base64 decode error: {0}")]
    Base64(SourceError),

    /// KMS could not encrypt or decrypt the private key.
    #[error(transparent)]
    Kms(#[from] KmsError),

    /// ejson could not encrypt or decrypt the document: an unsupported
    /// file extension, a file that is too large, a key that does not match,
    /// a corrupted value, and so on.
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
    /// The KMS `Decrypt` call failed: access denied, unknown key, a wrong
    /// encryption context, no credentials, a network failure, and so on.
    /// The payload displays the AWS SDK's full message, and its
    /// [source](std::error::Error::source) is the SDK's error.
    #[error("unable to decrypt parameter: {0}")]
    Decrypt(SourceError),

    /// The KMS `Encrypt` call failed; the payload is as for
    /// [`Decrypt`](Self::Decrypt).
    #[error("unable to encrypt parameter: {0}")]
    Encrypt(SourceError),

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

impl Error {
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

/// An error from one of the crates ejsonkms builds on: a parser, an encoder
/// or the AWS SDK.
///
/// The concrete type is hidden so that those crates are not part of the
/// ejsonkms API; upgrading one of them is then not a breaking change here.
/// It displays the underlying error's message.
pub struct SourceError(Box<dyn std::error::Error + Send + Sync + 'static>);

impl SourceError {
    pub(crate) fn new(err: impl std::error::Error + Send + Sync + 'static) -> Self {
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
