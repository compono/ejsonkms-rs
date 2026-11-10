//! A keypair whose private key is wrapped by KMS, and how to generate one.

use ejson::{FileFormat, Scheme};
use zeroize::Zeroizing;

use crate::{EjsonKmsError, document};

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
    /// encryption context.
    pub binding: KeyBinding,
}

impl std::fmt::Debug for EjsonKmsKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EjsonKmsKeys")
            .field("public_key", &self.public_key)
            .field("private_key_enc", &self.private_key_enc)
            .field("private_key", &"[REDACTED]")
            .field("scheme", &self.scheme)
            .field("binding", &self.binding)
            .finish()
    }
}

impl EjsonKmsKeys {
    /// Render a new, empty secrets file holding these keys: `_public_key`
    /// and the KMS-encrypted `_private_key_enc`, in the given format, plus
    /// `_kms_encryption_context` when the key is bound to the public key.
    ///
    /// The unencrypted private key is not part of the document.
    pub fn to_document(&self, format: FileFormat) -> Result<String, EjsonKmsError> {
        document::render(
            &self.public_key,
            &self.private_key_enc,
            self.binding,
            format,
        )
    }
}

/// What a KMS-encrypted private key is bound to, through the KMS
/// [encryption context](https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum KeyBinding {
    /// Nothing: KMS decrypts the private key for anyone allowed to use the
    /// KMS key, whichever file it is in. This is what every version of
    /// ejsonkms and the Go tool can read, and the default.
    #[default]
    Unbound,
    /// The file's public key, using the encryption context
    /// `ejsonkms_public_key = <public key>`.
    ///
    /// KMS then only decrypts the private key for a file that still has the
    /// same `_public_key`, so the wrapped key cannot be reused in another
    /// file, and IAM policies and CloudTrail can refer to the context. The
    /// file records this as `"_kms_encryption_context": "public_key"`.
    ///
    /// ejsonkms before 3.0 and the Go tool cannot decrypt a file created
    /// this way.
    PublicKey,
}

/// How [`Client::keygen`](crate::Client::keygen) should generate a keypair.
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
    /// What the KMS-encrypted private key is bound to; see [`KeyBinding`].
    pub binding: KeyBinding,
}

impl KeygenOptions {
    /// Set the key scheme.
    #[must_use]
    pub fn scheme(mut self, scheme: Scheme) -> Self {
        self.scheme = scheme;
        self
    }

    /// Set what the encrypted private key is bound to.
    #[must_use]
    pub fn binding(mut self, binding: KeyBinding) -> Self {
        self.binding = binding;
        self
    }
}
