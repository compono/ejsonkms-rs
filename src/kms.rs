//! AWS KMS integration for encrypting/decrypting the EJSON private key.

use aws_config::BehaviorVersion;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_kms::config::Region;
use aws_sdk_kms::error::DisplayErrorContext;
use aws_sdk_kms::primitives::Blob;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use zeroize::Zeroizing;

use crate::{EjsonKmsError, KmsError};

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
) -> Result<Zeroizing<String>, EjsonKmsError> {
    let encrypted_value = BASE64
        .decode(private_key_enc)
        .map_err(EjsonKmsError::base64)?;

    let mut request = kms_svc
        .decrypt()
        .ciphertext_blob(Blob::new(encrypted_value));
    if let Some(public_key) = bound_public_key {
        request = request.encryption_context(PUBLIC_KEY_CONTEXT, public_key);
    }
    let resp = request
        .send()
        .await
        .map_err(|e| KmsError::Decrypt(DisplayErrorContext(&e).to_string()))?;

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
) -> Result<String, EjsonKmsError> {
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
        .map_err(|e| KmsError::Encrypt(DisplayErrorContext(&e).to_string()))?;

    let ciphertext_blob = resp.ciphertext_blob().ok_or(KmsError::NoCiphertext)?;

    Ok(BASE64.encode(ciphertext_blob.as_ref()))
}
