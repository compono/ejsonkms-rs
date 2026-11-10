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

mod document;
mod error;
mod keys;
mod kms;

use std::path::Path;

use ejson::env::SecretEnvMap;
use ejson::{FileFormat, KeySource, UnderscorePrefix};
use zeroize::Zeroizing;

pub use error::{EjsonKmsError, KmsError, SourceError};
pub use keys::{EjsonKmsKeys, KeygenOptions, keygen};

use document::{detect_format, extract_private_key_enc, read_file_checked};
use kms::decrypt_private_key_with_kms;

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
