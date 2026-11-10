//! AWS KMS integration for encrypting/decrypting the EJSON private key.

use aws_config::meta::region::RegionProviderChain;
use aws_config::BehaviorVersion;
use aws_sdk_kms::config::Region;
use aws_sdk_kms::error::DisplayErrorContext;
use aws_sdk_kms::primitives::Blob;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use zeroize::Zeroizing;

use crate::{EjsonKmsError, KmsError};

/// Build a KMS client for the given region.
///
/// If `aws_region` is `None` (or empty), the default region provider chain
/// is used (`AWS_REGION`, `AWS_DEFAULT_REGION`, profile, etc.).
///
/// The endpoint comes from the AWS SDK's own configuration, so a local KMS
/// can be used for testing with `AWS_ENDPOINT_URL_KMS`.
async fn new_kms_client(aws_region: Option<&str>) -> aws_sdk_kms::Client {
    let region_provider = RegionProviderChain::first_try(
        aws_region
            .filter(|region| !region.is_empty())
            .map(|region| Region::new(region.to_string())),
    )
    .or_default_provider();

    let config = aws_config::defaults(BehaviorVersion::latest())
        .region(region_provider)
        .load()
        .await;
    aws_sdk_kms::Client::new(&config)
}

/// Decrypt a base64-encoded, KMS-encrypted private key.
///
/// The returned key is wrapped in [`Zeroizing`] so it is wiped from memory
/// when dropped.
pub(crate) async fn decrypt_private_key_with_kms(
    private_key_enc: &str,
    aws_region: Option<&str>,
) -> Result<Zeroizing<String>, EjsonKmsError> {
    let kms_svc = new_kms_client(aws_region).await;

    let encrypted_value = BASE64
        .decode(private_key_enc)
        .map_err(EjsonKmsError::base64)?;

    let resp = kms_svc
        .decrypt()
        .ciphertext_blob(Blob::new(encrypted_value))
        .send()
        .await
        .map_err(|e| KmsError::Decrypt(DisplayErrorContext(&e).to_string()))?;

    let plaintext = resp.plaintext().ok_or(KmsError::NoPlaintext)?;

    String::from_utf8(plaintext.as_ref().to_vec())
        .map(Zeroizing::new)
        .map_err(|_| KmsError::KeyNotUtf8.into())
}

/// Encrypt a private key with KMS and return it base64-encoded.
pub(crate) async fn encrypt_private_key_with_kms(
    private_key: &str,
    kms_key_id: &str,
    aws_region: Option<&str>,
) -> Result<String, EjsonKmsError> {
    let kms_svc = new_kms_client(aws_region).await;

    let resp = kms_svc
        .encrypt()
        .key_id(kms_key_id)
        .plaintext(Blob::new(private_key.as_bytes()))
        .send()
        .await
        .map_err(|e| KmsError::Encrypt(DisplayErrorContext(&e).to_string()))?;

    let ciphertext_blob = resp.ciphertext_blob().ok_or(KmsError::NoCiphertext)?;

    Ok(BASE64.encode(ciphertext_blob.as_ref()))
}
