//! `ejsonkms` combines the [ejson](https://github.com/runlevel5/ejson-rs) library with
//! [AWS Key Management Service](https://aws.amazon.com/kms/) to simplify deployments on AWS.
//!
//! The EJSON private key is encrypted with KMS and stored inside the EJSON file as
//! `_private_key_enc`. Access to decrypt secrets can be controlled with IAM permissions
//! on the KMS key.
//!
//! ```no_run
//! # async fn example() -> Result<(), ejsonkms::Error> {
//! // Region and credentials come from the usual AWS configuration.
//! let client = ejsonkms::Client::new().await;
//!
//! // Create a keypair whose private key is wrapped by a KMS key ...
//! let options = ejsonkms::KeygenOptions::default();
//! let keys = client.keygen("alias/my-key", &options).await?;
//! std::fs::write("secrets.ejson", keys.to_document(ejson::FileFormat::Json)?)?;
//!
//! // ... and later decrypt the file.
//! let plaintext = client.decrypt("secrets.ejson").await?;
//! let environment = client
//!     .decrypt_env("secrets.ejson", ejson::UnderscorePrefix::Keep)
//!     .await?;
//! # Ok(())
//! # }
//! ```
#![forbid(unsafe_code)]

// Compile the 3.0 examples in the upgrade guide as doctests, so the guide
// can't drift from the API.
#[cfg(doctest)]
#[doc = include_str!("../UPGRADING.md")]
struct UpgradingGuide;

mod client;
mod document;
mod error;
mod keys;
mod kms;
mod rewrap;

pub use client::{Client, ClientBuilder};
pub use error::{Error, KmsError, SourceError};

/// A `Result` whose error is [`enum@Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The previous name of [`enum@Error`].
#[deprecated(since = "3.0.0", note = "renamed to `ejsonkms::Error`")]
pub type EjsonKmsError = Error;
pub use keys::{EjsonKmsKeys, KeyBinding, KeygenOptions};
pub use rewrap::RewrapError;
