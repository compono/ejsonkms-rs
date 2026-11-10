//! AWS KMS integration for encrypting/decrypting the EJSON private key.

use aws_config::BehaviorVersion;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_kms::config::Region;
use aws_sdk_kms::primitives::Blob;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use zeroize::Zeroizing;

use crate::{Error, KmsError, Result, SourceError};

/// The KMS encryption context key that carries a file's public key.
pub(crate) const PUBLIC_KEY_CONTEXT: &str = "ejsonkms_public_key";

/// Build a KMS client.
///
/// With no `region` (or an empty one), the default region provider chain is
/// used (`AWS_REGION`, `AWS_DEFAULT_REGION`, profile, etc.). With no
/// `endpoint_url`, the endpoint comes from the AWS SDK's own configuration
/// (for example `AWS_ENDPOINT_URL_KMS`).
pub(crate) async fn new_kms_client(
    region: Option<&str>,
    endpoint_url: Option<&str>,
) -> aws_sdk_kms::Client {
    let region_provider = RegionProviderChain::first_try(
        region
            .filter(|region| !region.is_empty())
            .map(|region| Region::new(region.to_string())),
    )
    .or_default_provider();

    let mut loader = aws_config::defaults(BehaviorVersion::latest()).region(region_provider);
    if let Some(endpoint_url) = endpoint_url {
        loader = loader.endpoint_url(endpoint_url);
    }
    aws_sdk_kms::Client::new(&loader.load().await)
}

/// Decrypt a base64-encoded, KMS-encrypted private key.
///
/// The returned key is wrapped in [`Zeroizing`] so it is wiped from memory
/// when dropped.
///
/// `bound_public_key` is the public key the ciphertext was bound to when it
/// was encrypted, if any; KMS refuses to decrypt when it differs.
pub(crate) async fn decrypt_private_key_with_kms(
    kms_svc: &aws_sdk_kms::Client,
    private_key_enc: &str,
    bound_public_key: Option<&str>,
) -> Result<Zeroizing<String>> {
    let encrypted_value = BASE64.decode(private_key_enc).map_err(Error::base64)?;

    let mut request = kms_svc
        .decrypt()
        .ciphertext_blob(Blob::new(encrypted_value));
    if let Some(public_key) = bound_public_key {
        request = request.encryption_context(PUBLIC_KEY_CONTEXT, public_key);
    }
    let resp = request
        .send()
        .await
        .map_err(|e| KmsError::Decrypt(sdk_failure(e)))?;

    let plaintext = resp.plaintext().ok_or(KmsError::NoPlaintext)?;

    // Validate in place: the only copy made is the one that gets wiped.
    std::str::from_utf8(plaintext.as_ref())
        .map(|key| Zeroizing::new(key.to_owned()))
        .map_err(|_| KmsError::KeyNotUtf8.into())
}

/// Encrypt a private key with KMS and return it base64-encoded.
///
/// With `bound_public_key`, the ciphertext is bound to that public key
/// through the KMS encryption context and can only be decrypted by a request
/// that presents the same one.
pub(crate) async fn encrypt_private_key_with_kms(
    kms_svc: &aws_sdk_kms::Client,
    private_key: &str,
    kms_key_id: &str,
    bound_public_key: Option<&str>,
) -> Result<String> {
    let mut request = kms_svc
        .encrypt()
        .key_id(kms_key_id)
        .plaintext(Blob::new(private_key.as_bytes()));
    if let Some(public_key) = bound_public_key {
        request = request.encryption_context(PUBLIC_KEY_CONTEXT, public_key);
    }
    let resp = request
        .send()
        .await
        .map_err(|e| KmsError::Encrypt(sdk_failure(e)))?;

    let ciphertext_blob = resp.ciphertext_blob().ok_or(KmsError::NoCiphertext)?;

    Ok(BASE64.encode(ciphertext_blob.as_ref()))
}

/// An AWS SDK error, displayed with its whole chain of causes.
///
/// The SDK's own `Display` says only "service error" or "dispatch failure";
/// the useful part (the exception name and message, or the network error)
/// is in the sources.
#[derive(Debug)]
struct SdkFailure<E> {
    message: String,
    source: E,
}

impl<E> std::fmt::Display for SdkFailure<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl<E: std::error::Error + 'static> std::error::Error for SdkFailure<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

fn sdk_failure<E: std::error::Error + Send + Sync + 'static>(source: E) -> SourceError {
    SourceError::new(SdkFailure {
        message: error_chain(&source),
        source,
    })
}

/// `error`'s message followed by those of its sources, separated by ": ".
///
/// A cause whose message the previous one already ends with is skipped, so
/// a wrapper that repeats its source is not printed twice.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let cause_message = cause.to_string();
        if !cause_message.is_empty() && !message.ends_with(&cause_message) {
            message.push_str(": ");
            message.push_str(&cause_message);
        }
        source = cause.source();
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Layer(&'static str, Option<Box<Layer>>);

    impl std::fmt::Display for Layer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for Layer {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.1.as_deref().map(|layer| layer as _)
        }
    }

    #[test]
    fn test_error_chain_joins_causes_once() {
        let error = Layer(
            "service error",
            Some(Box::new(Layer(
                "AccessDeniedException: not authorized",
                Some(Box::new(Layer("not authorized", None))),
            ))),
        );
        assert_eq!(
            error_chain(&error),
            "service error: AccessDeniedException: not authorized"
        );
        assert_eq!(
            error_chain(&Layer("dispatch failure", None)),
            "dispatch failure"
        );
    }
}
